---
name: git-drafter
description: Draft (never run) git and GitHub write commands as reviewable, commented terminal blocks for a human to paste. Use whenever a git/GitHub write action is needed - commit, push, branch, tag, merge, rebase, reset, pull, PR create/merge, release, or any state-changing git/gh command. Read-only git/gh inspection is run normally, not drafted.
---

# git-drafter

## The rule
On this project, **Claude does not execute git or GitHub write actions.** It **drafts** them so a human can review
and paste them into their own terminal. Read-only inspection (`git status`, `git log`, `git diff`, `gh pr view`,
`gh api` GET, etc.) may be run normally.

A `PreToolUse` hook (`.claude/hooks/guard_git.py`) enforces this: if a write command is attempted through Bash, the
hook blocks it. Do not try to work around the hook — drafting is the intended path, not a fallback.

## When this applies
Any state-changing git/GitHub command, including: `commit`, `add`, `rm`, `mv`, `push`, `pull`, `fetch`+merge,
`merge`, `rebase`, `reset`, `revert`, `cherry-pick`, `branch` (create/delete/move), `checkout`/`switch` (new branch
or restore), `tag` (create/delete), `stash` (push/pop/apply/drop), `init`, `clone`, `remote` changes, `config`
writes, `submodule`/`worktree` changes, and GitHub CLI writes: `gh pr create|merge|close|edit|comment|review`,
`gh issue create|edit|close|comment`, `gh repo create|delete|fork|edit`, `gh release create|edit|delete`,
`gh api` with a write method (`-X POST|PUT|PATCH|DELETE`) or body fields (`-f`/`--field`).

## What to do instead: draft a reviewable block
When a write action is needed, output a single fenced `bash` block that the user can copy and paste. The block must
be **complete, self-contained, and safe to read at a glance**:

1. Start with a one-line **summary comment** of what the whole block does and why.
2. Precede each command (or small group) with a `#` comment explaining it in plain language.
3. Use the **exact** values (branch names, messages, paths) — no placeholders unless the user must choose; if a
   placeholder is unavoidable, mark it clearly like `<CHOOSE-BRANCH-NAME>` and say so beneath the block.
4. Prefer safe, explicit forms: create a branch rather than committing on `main`; show `git status`/`git diff`
   first; avoid `--force` unless the user asked, and if used, explain the risk on its own comment line.
5. After the block, add a short **"What this does / what to check first"** note and any follow-up commands
   (e.g., how to open a pull request) as their own block.
6. Never bundle unrelated writes into one block. One intention per block.

## Attribution (from the project's standing instruction)
When drafting a commit or a pull request, include the required trailer lines **inside the drafted block** so the
user's paste carries them:
- Commit message trailer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- Pull request description footer:
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
(If the project's own instructions specify different trailer lines, those take precedence.)

## Example (what a good draft looks like)

```bash
# Summary: save the new /docs planning set on a fresh branch (keeps main clean).
# 1) Confirm what will be committed before doing anything.
git status
git diff --stat

# 2) Create and switch to a topic branch so main is untouched.
git switch -c docs/ascend-planning

# 3) Stage only the docs and the .claude tooling we added.
git add docs/ .claude/

# 4) Commit with a descriptive message (trailer included as required).
git commit -m "docs: add ASCEND planning, defense, diagrams and git-drafter tooling

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

**What this does / check first:** creates branch `docs/ascend-planning`, stages `docs/` and `.claude/`, and commits.
Review `git status` output before running so you only commit what you intend. To publish and open a pull request
afterwards, ask and a separate `git push` + `gh pr create` block will be drafted.

## Do run (read-only) without drafting
`git status`, `git log`, `git diff`, `git show`, `git branch -a` (listing), `git remote -v`, `git config --get`,
`gh pr view|list|status|diff|checks`, `gh issue view|list`, `gh repo view`, `gh run view|list`, `gh api` (GET).
These help you see repository state and are safe to execute directly.
