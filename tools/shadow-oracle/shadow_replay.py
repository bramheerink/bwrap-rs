#!/usr/bin/env python3
"""Differential parity check: replay bwrap-rs invocations and, for each, compare
the sandbox plan bwrap-rs resolves against the plan upstream bubblewrap 0.13.1
would build. bwrap-rs does the real work in production; this tool only *reads* a
log of invocations and runs two side-effect-free dry-runs per entry:

  * bwrap-rs's plan  — `shadow_oracle` example with BWRAP_RS_DUMP=1 (a pure
    parse+resolve; no mounts/namespaces/exec).
  * bubblewrap's plan — a patched C bubblewrap with BWRAP_DRYRUN=1 (parses,
    validates, prints the plan it *would* build, exits before any setup).

Neither ever changes the system. Each genuine divergence is written as one JSON
object per line (JSONL) carrying the call, what each side did, and the diff — so
a line is greppable yet `jq .` expands it to a readable multi-line record.

See README.md for how to build the dry-run oracle.

Usage:
    BWRAP_RS_SHADOW=/path/to/bwrap-dryrun \\
        ./shadow_replay.py [--follow] [--tool PATH] [--results FILE] LOGFILE

Exit status is 0 when no genuine divergence was seen, 1 otherwise.
"""
import argparse, collections, json, os, shlex, subprocess, sys, time


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


def normalize(plan_text):
    """Comparable plan lines: trim, drop blanks, drop C's SET_HOSTNAME op
    (hostname is compared via the `hostname` header line)."""
    out = []
    for ln in plan_text.splitlines():
        ln = ln.rstrip()
        if not ln or ln.startswith("op SET_HOSTNAME"):
            continue
        out.append(ln)
    return out


def rs_side(args, tool):
    """bwrap-rs's plan via dump mode -> ('plan', [lines]) | ('error', msg) |
    ('nothing', reason)."""
    r = subprocess.run([tool, *args], env={**os.environ, "BWRAP_RS_DUMP": "1"},
                       capture_output=True, text=True, timeout=30)
    out = r.stdout
    first = out.splitlines()[0] if out.strip() else ""
    if first.startswith("__ERROR__"):
        return ("error", first[len("__ERROR__"):].strip())
    if first.startswith("__NOTHING__"):
        return ("nothing", first[len("__NOTHING__"):].strip())
    return ("plan", normalize(out))


def c_side(args, oracle):
    """bubblewrap's plan via dry-run -> ('plan', [lines]) | ('error', stderr)."""
    env = {k: v for k, v in os.environ.items() if k != "BWRAP_DRYRUN_FD"}
    env["BWRAP_DRYRUN"] = "1"
    r = subprocess.run([oracle, *args], env=env, capture_output=True, text=True, timeout=30)
    if r.returncode == 0 and r.stdout.strip():
        return ("plan", normalize(r.stdout))
    return ("error", " ".join(r.stderr.split()) or f"exit {r.returncode}")


def compare(rs, c):
    """Return (verdict, diff) where verdict in MATCH/MISMATCH/both-rejected/trivial."""
    rk, rv = rs
    ck, cv = c
    if rk == "nothing":
        return ("trivial", None)
    if rk == "plan" and ck == "plan":
        if rv == cv:
            return ("MATCH", None)
        diff = []
        for i in range(max(len(rv), len(cv))):
            a = rv[i] if i < len(rv) else None
            b = cv[i] if i < len(cv) else None
            if a != b:
                diff.append({"i": i, "rs": a, "c": b})
        return ("MISMATCH", diff)
    if rk == "error" and ck == "error":
        return ("both-rejected", None)
    return ("MISMATCH", None)  # one produced a plan, the other errored


def argvs_from_line(line):
    if " argv:" not in line:
        return None
    raw = line.split(" argv:", 1)[1].strip()
    try:
        toks = shlex.split(raw)
    except ValueError:
        return "unparseable"
    return toks[1:] if len(toks) > 1 else []


def record(side):
    """Shape one side ('plan'|'error'|'nothing', value) for the JSON output."""
    kind, val = side
    if kind == "plan":
        return {"outcome": "plan", "plan": val}
    if kind == "error":
        return {"outcome": "error", "error": val}
    return {"outcome": kind, "detail": val}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--tool", default=None)
    ap.add_argument("--results", default=None,
                    help="append one JSON object per divergence here (default: stdout)")
    args = ap.parse_args()

    oracle = os.environ.get("BWRAP_RS_SHADOW", "")
    if not oracle:
        sys.exit("shadow_replay: set BWRAP_RS_SHADOW=<path to the dry-run bwrap oracle>")
    tool = find_tool(args.tool)

    tally = collections.Counter()
    seen = set()
    had_mismatch = [False]
    results = open(args.results, "a") if args.results else sys.stdout

    def handle(line):
        av = argvs_from_line(line)
        if av is None:
            return
        if av == "unparseable":
            tally["unparseable-logline"] += 1
            return
        if not av:
            tally["no-args"] += 1
            return
        if any(a in ("--args", "--add-seccomp-fd") for a in av):
            tally["SKIP(--args/seccomp-fd)"] += 1
            return
        key = "\0".join(av)
        if key in seen:
            tally["dup"] += 1
            return
        seen.add(key)
        try:
            rs = rs_side(av, tool)
            c = c_side(av, oracle)
        except subprocess.TimeoutExpired:
            tally["timeout"] += 1
            return
        verdict, diff = compare(rs, c)
        tally[verdict] += 1
        if verdict == "MISMATCH":
            had_mismatch[0] = True
            obj = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "verdict": verdict,
                "argv": av,
                "bwrap_rs": record(rs),
                "bwrap_c": record(c),
            }
            if diff is not None:
                obj["diff"] = diff
            print(json.dumps(obj, ensure_ascii=False), file=results, flush=True)

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

    return 1 if had_mismatch[0] else 0


def print_tally(tally):
    print("\n=== shadow-oracle tally (unique invocations) ===", file=sys.stderr)
    for k, v in tally.most_common():
        print(f"  {v:7d}  {k}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
