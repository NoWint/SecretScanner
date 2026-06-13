# SecretScannerCLI Design

## Overview

SecretScannerCLI 是一个 Go 语言实现的代码仓库密钥扫描工具。递归扫描 git 历史，检测 API Key/Token/密码泄露，支持 pre-commit hook 阻断提交。

## Architecture: Monolithic CLI

单一 Go 二进制文件，内部模块化分层。使用 go-git 纯 Go 实现，无系统 git 依赖。

## Project Structure

```
SecretScanner/
├── cmd/
│   └── root.go          # Cobra 根命令 + 子命令注册
├── internal/
│   ├── scanner/
│   │   ├── scanner.go   # 扫描引擎：正则匹配 + 熵值分析
│   │   └── scanner_test.go
│   ├── git/
│   │   ├── walker.go    # Git 历史遍历（go-git）
│   │   └── walker_test.go
│   ├── rules/
│   │   ├── builtin.go   # 内置规则定义
│   │   ├── loader.go    # YAML 自定义规则加载
│   │   └── rules_test.go
│   ├── report/
│   │   ├── table.go     # 终端彩色表格输出
│   │   ├── json.go      # JSON 输出
│   │   └── report_test.go
│   └── hook/
│       ├── install.go   # pre-commit hook 安装
│       └── hook_test.go
├── configs/
│   └── rules.yaml       # 自定义规则示例文件
├── main.go              # 入口
├── go.mod
└── go.sum
```

## CLI Commands

| 命令 | 说明 |
|------|------|
| `secretscanner scan <path>` | 扫描指定仓库（默认当前目录），支持 `--format=table|json`、`--rules=<yaml>` |
| `secretscanner install-hook` | 在当前 git 仓库安装 pre-commit hook |
| `secretscanner version` | 显示版本信息 |

### Scan Flags

- `--format=table|json` — 输出格式，默认 table
- `--rules=<yaml>` — 自定义规则文件路径
- `--no-history` — 仅扫描工作区文件，不扫描 git 历史
- `--staged` — 仅扫描暂存区文件（pre-commit hook 使用）

## Core Dependencies

- `github.com/spf13/cobra` — CLI 框架
- `github.com/go-git/go-git/v5` — 纯 Go Git 实现
- `github.com/fatih/color` — 终端彩色输出
- `gopkg.in/yaml.v3` — YAML 规则解析

## Scanner Engine

扫描引擎接收文本内容 + 文件路径，返回匹配到的泄露列表。

### Core Flow

1. 遍历所有规则（内置 + 自定义），对文本执行正则匹配
2. 对每个匹配结果计算 Shannon 熵值，与规则阈值比较
3. 组装 Finding 结构体返回

### Data Structures

```go
type Finding struct {
    RuleID      string  // 规则 ID
    RuleName    string  // 规则名称
    Severity    string  // high / medium / low
    FilePath    string  // 文件路径
    LineNumber  int     // 行号
    Match       string  // 匹配到的原始字符串
    Entropy     float64 // Shannon 熵值
    CommitHash  string  // 所在 commit（历史扫描时填充）
}

type Rule struct {
    ID          string          // 唯一标识，如 "aws-access-key"
    Name        string          // 规则名称
    Pattern     *regexp.Regexp  // 正则表达式
    EntropyMin  float64         // 最低熵值阈值，0 表示不做熵值检查
    Severity    string          // high / medium / low
    Keywords    []string        // 关键词，用于快速预过滤
}
```

## Built-in Rules

| 类别 | 示例规则 |
|------|---------|
| Cloud Provider | AWS Access Key / Secret Key, Azure Token, GCP Service Account Key |
| VCS | GitHub Token (ghp_/gho_/ghu_/ghs_), GitLab Token, Bitbucket Token |
| Messaging | Slack Token/Bot Token, Discord Token |
| Database | MongoDB URI, PostgreSQL URI, MySQL URI |
| Payment | Stripe Key, PayPal Token |
| Crypto | Private Key (BEGIN RSA/EC/DSA PRIVATE KEY) |
| Generic | High-entropy string (熵值 > 4.5 的长字符串) |

## Custom Rules Format (YAML)

```yaml
rules:
  - id: my-api-key
    name: My Custom API Key
    pattern: "my_api_key\\s*=\\s*['\"]([A-Za-z0-9]{32,})['\"]"
    entropy_min: 3.5
    severity: high
    keywords:
      - my_api_key
```

## Entropy Calculation

标准 Shannon 熵公式，对匹配到的字符串计算字符频率分布，输出 0-8 的浮点数。高熵值（>4.5）通常表示随机生成的密钥。

## Git History Walker

使用 go-git 打开仓库，遍历所有 commit 的 diff：

1. `git.PlainOpen(path)` 打开仓库
2. `repo.Log()` 获取 commit 迭代器
3. 对每个 commit，获取其与父 commit 的 `object.Diff`
4. 对 diff 中的每个 `Patch`，提取新增/修改的文件内容
5. 将内容传入扫描引擎检测
6. 收集所有 Finding，附加 CommitHash、CommitTime、Author 信息

### Scan Modes

| 模式 | 触发方式 | 扫描范围 |
|------|---------|---------|
| 历史全量扫描 | `secretscanner scan <path>` | 所有 commit 的 diff |
| 工作区扫描 | `secretscanner scan <path> --no-history` | 仅当前工作区文件 |
| Pre-commit 扫描 | hook 自动触发 | 仅暂存区文件（通过 go-git staging area API 获取） |

## Pre-commit Hook

`secretscanner install-hook` 执行流程：

1. 检测当前目录是否为 git 仓库
2. 在 `.git/hooks/` 目录创建 `pre-commit` 文件
3. 写入脚本：`secretscanner scan --staged --no-history --format=table`
4. 设置可执行权限

Hook 行为：
- `--staged` 标志：仅扫描暂存区文件（通过 go-git staging area API 获取文件列表）
- 发现泄露：输出结果，退出码 1，阻止提交
- 未发现泄露：静默通过，退出码 0

## Ignore Mechanism

支持 `.secretscannerignore` 文件（格式同 .gitignore），排除无需扫描的路径（如 `*.lock`、`vendor/`、`node_modules/` 等）。

## Output Formats

### Terminal Table (default)

```
╭──────────────────────────────────────────────────────────────╮
│  SecretScanner — Found 3 secrets                              │
╰──────────────────────────────────────────────────────────────╯

[HIGH] AWS Access Key ID
  File:   src/config/aws.go:42
  Match:  AKIA3E...7XMQ
  Commit: a1b2c3d (2024-01-15)
  Entropy: 4.72

[MEDIUM] Generic High-Entropy String
  File:   .env:7
  Match:  dG9rZW5f...xYzEyMw==
  Entropy: 5.31

[LOW] Private Key
  File:   secrets/id_rsa
  Match:  -----BEGIN RSA PRIVATE KEY-----
```

- HIGH 红色、MEDIUM 黄色、LOW 蓝色
- Match 字段自动截断，敏感值部分掩码显示（默认显示前6位 + ... + 后4位）

### JSON Output (`--format=json`)

```json
{
  "version": "1.0.0",
  "scan_time": "2024-01-15T10:30:00Z",
  "repository": "/path/to/repo",
  "total_findings": 3,
  "findings": [
    {
      "rule_id": "aws-access-key",
      "rule_name": "AWS Access Key ID",
      "severity": "high",
      "file_path": "src/config/aws.go",
      "line_number": 42,
      "match": "AKIA3E...7XMQ",
      "entropy": 4.72,
      "commit_hash": "a1b2c3d",
      "commit_time": "2024-01-15T08:00:00Z",
      "author": "developer@example.com"
    }
  ]
}
```

## Exit Codes

| 退出码 | 含义 |
|--------|------|
| 0 | 未发现泄露 |
| 1 | 发现泄露 |
| 2 | 扫描出错（无效路径、不是 git 仓库等） |

## Error Handling

- 非法路径 / 非 git 仓库：输出友好错误信息，退出码 2
- 自定义规则文件解析失败：输出具体行号和原因，退出码 2
- 单个文件扫描出错（二进制文件、权限不足）：跳过并记录 warning，不中断整体扫描
