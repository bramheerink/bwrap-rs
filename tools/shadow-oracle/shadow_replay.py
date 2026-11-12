#!/usr/bin/env python3
"""Differential parity check: replay bwrap-rs invocations through a dry-run
bubblewrap 0.13.1 oracle and diff the sandbox plan each would build.

bwrap-rs does the real work in production; this tool only *reads* a log of
invocations and, for each, (a) asks the bwrap-rs library what plan it resolves
(a pure, side-effect-free parse+resolve, via the `shadow_oracle` example) and
(b) asks a patched C bubblewrap what plan it *would* build (dry-run: it parses,
validates, prints the plan and exits before any mount/namespace/exec). The two
plans are compared. Nothing is ever actually sandboxed by this tool, and the C
oracle never changes anything.

See README.md for how to build the dry-run oracle.

Usage:
    BWRAP_RS_SHADOW=/path/to/bwrap-dryrun \\
        ./shadow_replay.py [--follow] [--tool PATH] LOGFILE

    --follow      keep running, diffing new invocations as they are logged
    --tool PATH   the built `shadow_oracle` example (default: autodetect under
                  target/{release,debug}/examples/)

Exit status is 0 when no genuine divergence was seen, 1 otherwise.
"""
import argparse, collections, os, shlex, subprocess, sys, time


def find_tool(explicit):
    if explicit:
        return explicit
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))  # repo root
    for sub in ("release", "debug"):
        cand = os.path.join(root, "target", sub, "examples", "shadow_oracle")
        if os.path.exists(cand):
            return cand
    sys.exit("shadow_replay: could not find the shadow_oracle example; build it with\n"
             "  cargo build --release --example shadow_oracle -p bwrap-cli\n"
             "or pass --tool PATH")


def classify(args, tool, oracle):
    try:
        r = subprocess.run([tool, *args], env={**os.environ, "BWRAP_RS_SHADOW": oracle},
                           capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "timeout", ""
    out = r.stdout.strip()
    first = out.split("\n", 1)[0] if out else "(no output)"
    if first.startswith("MATCH"):
        return "MATCH", out
    if first.startswith("SKIP"):
        return "SKIP", out
    if first.startswith("MISMATCH"):
        return "MISMATCH", out
    if "also errored" in out:
        return "both-rejected", out
    if first.startswith("nothing to compare"):
        return "trivial", out
    if first.startswith("bwrap-rs:"):
        # one side errored but not matched as both-rejected
        return "MISMATCH", out
    return "other", out


def argvs_from_line(line):
    if " argv:" not in line:
        return None
    raw = line.split(" argv:", 1)[1].strip()
    try:
        toks = shlex.split(raw)
    except ValueError:
        return "unparseable"
    return toks[1:] if len(toks) > 1 else []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--tool", default=None)
    ap.add_argument("--results", default=None,
                    help="append MISMATCH/verdict detail to this file (default: stderr)")
    args = ap.parse_args()

    oracle = os.environ.get("BWRAP_RS_SHADOW", "")
    if not oracle:
        sys.exit("shadow_replay: set BWRAP_RS_SHADOW=<path to the dry-run bwrap oracle>")
    tool = find_tool(args.tool)

    tally = collections.Counter()
    seen = set()
    had_mismatch = False
    results = open(args.results, "a") if args.results else sys.stderr

    def handle(line):
        nonlocal had_mismatch
        av = argvs_from_line(line)
        if av is None:
            return
        if av == "unparseable":
            tally["unparseable-logline"] += 1
            return
        if not av:
            tally["no-args"] += 1
            return
        key = "\0".join(av)
        if key in seen:
            tally["dup"] += 1
            return
        seen.add(key)
        verdict, out = classify(av, tool, oracle)
        tally[verdict] += 1
        if verdict in ("MISMATCH", "other", "timeout"):
            had_mismatch = had_mismatch or verdict == "MISMATCH"
            shown = " ".join(av)
            if len(shown) > 300:
                shown = shown[:300] + " …"
            print(f"[{time.strftime('%H:%M:%S')}] {verdict}\n  ARGS: {shown}\n{out}\n",
                  file=results, flush=True)

    with open(args.log, "r", errors="replace") as f:
        for line in f:
            handle(line)
        print_tally(tally)
        if args.follow:
            print("--- following for new invocations (Ctrl-C to stop) ---", file=sys.stderr)
            try:
                while True:
                    line = f.readline()
                    if line:
                        handle(line)
                    else:
                        time.sleep(1.0)
            except KeyboardInterrupt:
                print_tally(tally)

    return 1 if had_mismatch else 0


def print_tally(tally):
    print("\n=== shadow-oracle tally (unique invocations) ===", file=sys.stderr)
    for k, v in tally.most_common():
        print(f"  {v:7d}  {k}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
