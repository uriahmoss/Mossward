# Continue Mossward on Another PC

This guide transfers the source, roadmap, and Codex project rules through the
GitHub repository. It does not transfer runtime databases, private keys,
certificates, `.env` files, enrollment tokens, or other secrets.

## 1. Install prerequisites

Install:

- Git
- Go 1.26 or newer
- Codex, if Codex will be used for development
- Optional: GNU Make for the repository's convenience commands
- Optional: GitHub CLI (`gh`) for GitHub authentication

Confirm the required tools:

```sh
git --version
go version
```

## 2. Configure GitHub write access

The repository is:

```text
https://github.com/uriahmoss/Mossward.git
```

Cloning may work without authentication when the repository is public. Pushing
requires a GitHub account with write access. Configure either:

- GitHub CLI: `gh auth login`
- An SSH key registered with GitHub, then use the SSH repository URL
- A credential-manager-backed HTTPS login

Do not place a GitHub token in a repository file or shell script.

## 3. Clone the repository

Choose a normal development directory, then run:

```sh
git clone https://github.com/uriahmoss/Mossward.git
cd Mossward
git status --short --branch
git log -5 --oneline
```

The expected branch is `main`. Confirm it tracks `origin/main` and has no local
changes before starting work.

## 4. Download dependencies and verify the project

```sh
go mod download
go test ./...
go vet ./...
go build ./cmd/mossward ./cmd/mossward-agent
git diff --check
```

When GNU Make is installed, the normal equivalent is:

```sh
make verify
make build
```

Generated binaries and runtime data should remain ignored by Git.

## 5. Resume with Codex

Open the cloned `Mossward` directory as the Codex workspace. The root
`AGENTS.md` contains the project rules and is versioned with the source.

Use this initial request:

```text
Read AGENTS.md and docs/FEATURES.md. Fetch origin and compare local main with
origin/main. Review the working tree for missing or overwritten changes, run
the verification checks, and tell me the next incomplete recommended slice
before making changes.
```

Codex global rules are machine-local. The repository `AGENTS.md` is sufficient
for Mossward, but copy any additional personal global rules into the new
computer's Codex global `AGENTS.md` if desired.

## 6. Create machine-local configuration

Start from the tracked examples rather than copying secrets into Git:

```sh
cp config/mossward.env.example .env
cp config/mossward-agent.json.example mossward-agent.json
```

Review the selected deployment documentation before enabling hosted access:

- `docs/DEPLOYMENT.md`
- `docs/SERVICE_INSTALLATION.md`
- `docs/ENDPOINT_AGENT.md`
- `docs/BACKUP_RESTORE.md`

Generate new development keys and certificates on the new PC when practical.
If existing production state must be moved, use Mossward's protected backup and
restore process and a secure out-of-band transfer. Never commit these items:

- `data/` databases and runtime state
- `.env` files
- identity-encryption keys
- endpoint or server private keys
- ACME account state
- recovery codes, passwords, API keys, or enrollment tokens

Without access to the original PC or a protected backup, its runtime database,
local accounts, certificates, and enrolled-agent identity cannot be recovered
from GitHub. Development can still continue from the full source and roadmap.

## 7. Normal synchronization workflow

Before beginning a work session:

```sh
git switch main
git pull --ff-only origin main
git status --short --branch
```

After a verified slice:

```sh
git add <reviewed-files>
git commit -m "Describe the completed slice"
git push origin main
```

Do not use destructive Git commands to resolve divergence. Inspect the local
and remote histories first, then merge or rebase only after reviewing the
changes that would be affected.
