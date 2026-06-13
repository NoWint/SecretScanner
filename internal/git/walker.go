package git

import (
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/NoWint/SecretScanner/internal/rules"
	"github.com/NoWint/SecretScanner/internal/scanner"
)

// ScanRepository scans all commits in a git repository for secrets.
func ScanRepository(path string, ruleSet []rules.Rule) ([]rules.Finding, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("opening repository at %s: %w", path, err)
	}

	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("getting HEAD: %w", err)
	}

	commitIter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil, fmt.Errorf("getting commit log: %w", err)
	}
	defer commitIter.Close()

	seen := make(map[string]bool)
	var allFindings []rules.Finding

	err = commitIter.ForEach(func(c *object.Commit) error {
		if c.NumParents() == 0 {
			tree, err := c.Tree()
			if err != nil {
				return nil
			}
			tree.Files().ForEach(func(f *object.File) error {
				if seen[f.Name] {
					return nil
				}
				seen[f.Name] = true
				content, err := f.Contents()
				if err != nil {
					return nil
				}
				findings := scanner.ScanContent(content, f.Name, ruleSet)
				for i := range findings {
					findings[i].CommitHash = c.Hash.String()[:7]
					findings[i].Date = c.Author.When.Format("2006-01-02")
					findings[i].Author = c.Author.Email
				}
				allFindings = append(allFindings, findings...)
				return nil
			})
			return nil
		}

		parent, err := c.Parent(0)
		if err != nil {
			return nil
		}

		patch, err := parent.Patch(c)
		if err != nil {
			return nil
		}

		for _, fp := range patch.FilePatches() {
			from, to := fp.Files()
			if to == nil {
				continue
			}
			var filePath string
			if from != nil {
				filePath = from.Path()
			} else {
				filePath = to.Path()
			}

			var content string
			for _, chunk := range fp.Chunks() {
				if chunk.Type() == diff.Add {
					content += chunk.Content() + "\n"
				}
			}
			if content == "" {
				continue
			}

			findings := scanner.ScanContent(content, filePath, ruleSet)
			for i := range findings {
				findings[i].CommitHash = c.Hash.String()[:7]
				findings[i].Date = c.Author.When.Format("2006-01-02")
				findings[i].Author = c.Author.Email
			}
			allFindings = append(allFindings, findings...)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("iterating commits: %w", err)
	}

	return allFindings, nil
}

// ScanWorkingDirectory scans only the current working directory files.
func ScanWorkingDirectory(path string, ruleSet []rules.Rule) ([]rules.Finding, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("opening repository at %s: %w", path, err)
	}

	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("getting HEAD: %w", err)
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("getting commit: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("getting tree: %w", err)
	}

	var allFindings []rules.Finding
	err = tree.Files().ForEach(func(f *object.File) error {
		content, err := f.Contents()
		if err != nil {
			return nil
		}
		findings := scanner.ScanContent(content, f.Name, ruleSet)
		allFindings = append(allFindings, findings...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking tree: %w", err)
	}

	return allFindings, nil
}

// ScanStagedFiles scans only the files in the staging area.
func ScanStagedFiles(path string, ruleSet []rules.Rule) ([]rules.Finding, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("opening repository at %s: %w", path, err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("getting worktree: %w", err)
	}

	status, err := wt.Status()
	if err != nil {
		return nil, fmt.Errorf("getting status: %w", err)
	}

	var allFindings []rules.Finding
	for filePath, s := range status {
		if s.Staging != git.Added && s.Staging != git.Modified && s.Staging != git.Renamed && s.Staging != git.Copied {
			continue
		}

		idx, err := repo.Storer.Index()
		if err != nil {
			continue
		}

		var objHash plumbing.Hash
		for _, e := range idx.Entries {
			if e.Name == filePath {
				objHash = e.Hash
				break
			}
		}
		if objHash.IsZero() {
			continue
		}

		blob, err := repo.BlobObject(objHash)
		if err != nil {
			continue
		}

		r, err := blob.Reader()
		if err != nil {
			continue
		}

		buf := make([]byte, blob.Size)
		n, _ := r.Read(buf)
		r.Close()

		content := string(buf[:n])
		findings := scanner.ScanContent(content, filePath, ruleSet)
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}
