# Security policy

## Status

bwrap-rs is pre-1.0 and pre-adoption. It is a drop-in reimplementation of a
security-critical tool — the unprivileged sandbox behind Flatpak — so security
reports are very welcome and taken seriously even at this stage.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not as a public issue.

- Use GitHub's private vulnerability reporting — "Report a vulnerability" under
  the repository's **Security** tab — which opens a private advisory thread.

Include, where you can: the exact command line and inputs (an `--args` file if
relevant), the bwrap-rs commit or version, the kernel and distribution, and what
you observed versus what you expected. A minimal reproducer is the single most
useful thing you can send.

## Scope

**In scope** — anything that lets a sandboxed process:

- escape the sandbox or gain a privilege it was not granted;
- read or affect the host beyond the sandbox's configuration; or
- makes bwrap-rs behave *less* safely than bubblewrap 0.13.1 does for the **same
  arguments**. (Intended, documented deviations live in
  [DIFFERENCES.md](DIFFERENCES.md); a divergence not listed there is a bug.)

**Out of scope / the caller's responsibility** (exactly as for upstream
bubblewrap — the sandbox is only as strong as the arguments it is given; see
[THREAT-MODEL.md](THREAT-MODEL.md)):

- terminal injection (TIOCSTI/TIOCLINUX) when `--new-session` is not passed;
- an absent or incomplete `--seccomp` / `--add-seccomp-fd` filter;
- not passing `--disable-userns`;
- kernel vulnerabilities reachable through the namespaces themselves.

## Handling

As a pre-adoption project the response is best-effort, but the intent mirrors
upstream's: confirm the report, fix it in coordination with the reporter, and
publish without undue delay. If bwrap-rs is ever shipped as a distribution's
`/usr/bin/bwrap`, this policy will be upgraded to a committed response timeline
and a proper CVE / advisory process.
