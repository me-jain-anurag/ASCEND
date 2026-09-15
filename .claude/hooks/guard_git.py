#!/usr/bin/env python3
"""
guard_git.py — PreToolUse hook for the `git-drafter` skill.

Purpose
-------
The team's rule: **Claude never RUNS git/GitHub write actions.** It DRAFTS them
(as reviewable, commented terminal commands) and a human pastes them. Read-only
git/GitHub inspection is allowed so Claude can still see repository state.

This hook is the safety net that enforces that rule. It inspects every Bash
command Claude tries to run and BLOCKS it if it contains a git or GitHub-CLI
WRITE operation, telling Claude to draft the command instead. Anything that is
not a git/gh write — including all read-only git/gh commands — is allowed.

Contract
--------
Reads a JSON object on stdin: {"tool_name": "...", "tool_input": {"command": "..."}}
- To BLOCK: print a reason to stderr and exit with code 2.
- To ALLOW: exit 0 with no output.

Design: FAIL CLOSED for git/gh. If a git/gh subcommand is not on the known
read-only list, it is treated as a write and blocked. Non-git/gh commands pass.
"""

import json
import re
import shlex
import sys

# ---- git subcommands that only READ (safe to run) -----------------------
GIT_READ_ONLY = {
    "status", "log", "diff", "show", "rev-parse", "rev-list", "ls-files",
    "ls-tree", "cat-file", "blame", "describe", "shortlog", "for-each-ref",
    "name-rev", "merge-base", "whatchanged", "grep", "reflog", "count-objects",
    "fsck", "help", "version", "symbolic-ref", "var", "check-ignore",
    "check-attr", "verify-commit", "verify-tag", "get-tar-commit-id", "cherry",
    "range-diff", "show-ref", "show-branch", "annotate", "diff-tree",
    "diff-index", "diff-files", "instaweb", "fetch",  # fetch: read-only network
}

# ---- git subcommands that are read-ONLY only with certain args ----------
# These need argument inspection: bare/listing form reads, other forms write.
GIT_CONDITIONAL = {"branch", "tag", "config", "remote", "stash", "worktree",
                   "submodule", "notes", "bisect"}

# ---- gh (GitHub CLI) read verbs (per resource) --------------------------
GH_READ_VERBS = {"view", "list", "status", "diff", "checks", "browse",
                 "search", "get"}

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def deny(reason):
    sys.stderr.write(reason.strip() + "\n")
    sys.exit(2)


def allow():
    sys.exit(0)


def split_segments(command):
    """Split a shell command into pipeline/sequence segments so each is
    classified independently. Good enough for cooperative use."""
    return re.split(r"&&|\|\||;|\n|(?<!\|)\|(?!\|)", command)


def strip_redirections(seg):
    """Remove shell redirection tokens (2>&1, >file, 2>/dev/null, >>log, <in)
    so they are not mistaken for command arguments (e.g. a branch name)."""
    # fd duplication: 2>&1, >&2, 1>&2
    seg = re.sub(r"\d*>&\d*", " ", seg)
    # redirection operator followed by a target: > file, 2>> log, < input
    seg = re.sub(r"(?:\d*>>?|&>>?|<)\s*\S+", " ", seg)
    # any bare/trailing redirection operator
    seg = re.sub(r"(?:\d*>>?|&>>?|<)", " ", seg)
    # trailing background/control operators
    seg = re.sub(r"(?<!\S)&(?!\S)", " ", seg)
    return seg


def strip_leading_noise(tokens):
    """Drop env-assignments and sudo/command wrappers before the real cmd."""
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):   # FOO=bar
            i += 1
            continue
        if t in ("sudo", "command", "env", "nice", "nohup", "time", "stdbuf",
                 "xargs", "then", "do", "!"):
            i += 1
            continue
        break
    return tokens[i:]


def classify_git(args):
    """Return None if allowed, or a string reason if it is a write."""
    # find first non-option token = the subcommand (skip -C <path>, -c k=v, etc.)
    sub = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-C", "--git-dir", "--work-tree", "--namespace"):
            i += 2
            continue
        if a == "-c":            # -c key=value inline config
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        sub = a
        rest = args[i + 1:]
        break
    else:
        return None  # bare `git` — harmless (prints help)

    if sub in GIT_READ_ONLY:
        return None

    if sub in GIT_CONDITIONAL:
        return classify_git_conditional(sub, rest)

    # unknown / everything else -> treat as a write (fail closed)
    return f"`git {sub}` changes repository or remote state"


def _has_positional(rest):
    return any(not a.startswith("-") for a in rest)


def classify_git_conditional(sub, rest):
    if sub == "branch":
        write_flags = {"-d", "-D", "-m", "-M", "-c", "-C", "--delete",
                       "--move", "--copy", "--set-upstream-to", "-u",
                       "--unset-upstream", "--edit-description", "-f", "--force"}
        if any(a in write_flags for a in rest) or _has_positional(rest):
            return "`git branch` here creates/deletes/moves a branch (a write)"
        return None
    if sub == "tag":
        listing = all(a in ("-l", "--list", "-n", "--contains", "--points-at",
                            "--sort", "--merged", "--no-merged") or a.startswith("-n")
                      for a in rest)
        if rest and not listing:
            return "`git tag` here creates/deletes a tag (a write)"
        if any(a in ("-d", "--delete", "-a", "-s", "-f", "--force") for a in rest):
            return "`git tag` here creates/deletes a tag (a write)"
        return None
    if sub == "config":
        read_flags = {"--get", "--get-all", "--get-regexp", "--get-urlmatch",
                      "--list", "-l"}
        if any(a in read_flags for a in rest):
            return None
        return "`git config` here writes configuration"
    if sub == "remote":
        if not rest or rest[0] in ("-v", "--verbose", "show", "get-url"):
            return None
        return "`git remote` here modifies remotes (a write)"
    if sub == "stash":
        if rest and rest[0] in ("list", "show"):
            return None
        return "`git stash` here modifies the working tree/stash (a write)"
    if sub == "worktree":
        if rest and rest[0] == "list":
            return None
        return "`git worktree` here adds/removes a worktree (a write)"
    if sub == "submodule":
        if rest and rest[0] in ("status", "summary"):
            return None
        return "`git submodule` here changes submodules (a write)"
    if sub in ("notes", "bisect"):
        return f"`git {sub}` changes repository state"
    return f"`git {sub}` may change repository state"


def classify_gh(args):
    """Return None if allowed (read-only), or a reason string if it is a write."""
    # skip global gh flags
    positional = [a for a in args if not a.startswith("-")]
    if not positional:
        return None  # bare `gh` prints help
    resource = positional[0]
    verb = positional[1] if len(positional) > 1 else None

    if resource in ("auth",):
        if verb == "status":
            return None
        return "`gh auth` changes authentication state"

    if resource == "api":
        # read only if no write method and no write body fields
        joined = " ".join(args)
        m = re.search(r"(?:-X|--method)\s+(\w+)", joined)
        if m and m.group(1).upper() in WRITE_METHODS:
            return "`gh api` with a write method changes GitHub state"
        if re.search(r"(?:^|\s)(-f|--field|--input|--raw-field|-F)(\s|=)", joined):
            return "`gh api` with body fields performs a write"
        return None

    # resource-verb style: allow known read verbs
    if verb in GH_READ_VERBS:
        return None
    if verb is None:
        return None  # e.g. `gh pr` prints help
    return f"`gh {resource} {verb}` performs a GitHub write action"


def classify_segment(seg):
    seg = strip_redirections(seg)
    try:
        tokens = shlex.split(seg, comments=True)
    except ValueError:
        tokens = seg.split()
    tokens = strip_leading_noise(tokens)
    if not tokens:
        return None
    prog = tokens[0]
    # allow explicit paths like /usr/bin/git
    base = prog.rsplit("/", 1)[-1]
    if base == "git":
        return classify_git(tokens[1:])
    if base == "gh":
        return classify_gh(tokens[1:])
    return None


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        allow()  # cannot parse -> do not block
    if payload.get("tool_name") != "Bash":
        allow()
    command = (payload.get("tool_input") or {}).get("command", "")
    if not command:
        allow()

    for seg in split_segments(command):
        reason = classify_segment(seg)
        if reason:
            deny(
                "BLOCKED by git-drafter: " + reason + ".\n"
                "Per the team's rule, do not RUN git/GitHub write actions. "
                "Instead, invoke the `git-drafter` skill and DRAFT the command "
                "as a commented, copy-pasteable block for the user to review and "
                "run themselves. Read-only git/gh inspection is allowed."
            )
    allow()


if __name__ == "__main__":
    main()
