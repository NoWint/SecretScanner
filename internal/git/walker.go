package git

import (
	"fmt"
	"io"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/NoWint/SecretScanner/internal/rules"
	"github.com/NoWint/SecretScanner/internal/scanner"
)

// dedupKey creates a unique key for a finding to deduplicate across commits.
func dedupKey(f rules.Finding) string {
	return f.RuleID + ":" + f.FilePath + ":" + f.Match
}

// appendDedup adds findings, skipping duplicates based on (ruleID, filePath, match).
func appendDedup(allFindings []rules.Finding, findings []rules.Finding, dedup map[string]bool) []rules.Finding {
	for _, f := range findings {
		key := dedupKey(f)
		if dedup[key] {
			continue
		}
		dedup[key] = true
		allFindings = append(allFindings, f)
	}
	return allFindings
}

// ProgressFunc is called periodically during scanning to report progress.
// scanned is the number of commits scanned so far.
type ProgressFunc func(scanned int)

// ScanRepository scans all commits in a git repository for secrets.
// If progress is not nil, it is called after each commit is processed.
func ScanRepository(path string, ruleSet []rules.Rule, progress ProgressFunc) ([]rules.Finding, error) {
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
	// Deduplicate findings: same (ruleID, filePath, match) only reported once
	dedup := make(map[string]bool)
	var allFindings []rules.Finding
	scanned := 0

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
					findings[i].CommitTime = c.Author.When.Format("2006-01-02")
					findings[i].Author = c.Author.Email
				}
				allFindings = appendDedup(allFindings, findings, dedup)
				return nil
			})
			return nil
		}

		// Diff against all parents to catch secrets from merged branches
		for pIdx := 0; pIdx < c.NumParents(); pIdx++ {
			parent, err := c.Parent(pIdx)
			if err != nil {
				continue
			}

			patch, err := parent.Patch(c)
			if err != nil {
				continue
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
					findings[i].CommitTime = c.Author.When.Format("2006-01-02")
					findings[i].Author = c.Author.Email
				}
				allFindings = appendDedup(allFindings, findings, dedup)
			}
		}
		scanned++
		if progress != nil {
			progress(scanned)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("iterating commits: %w", err)
	}

	return allFindings, nil
}

// ScanWorkingDirectory scans only the current working directory files.
func ScanWorkingDirectory(path string, ruleSet []rules.Rule, _ ProgressFunc) ([]rules.Finding, error) {
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
func ScanStagedFiles(path string, ruleSet []rules.Rule, _ ProgressFunc) ([]rules.Finding, error) {
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

		content, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			continue
		}

		findings := scanner.ScanContent(string(content), filePath, ruleSet)
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}
