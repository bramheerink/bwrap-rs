#!/usr/bin/env python3
"""Patch a copy of bubblewrap.c to add the bwrap-rs dry-run plan oracle.

Additive and env-gated: with BWRAP_DRYRUN unset the binary behaves identically.
With it set, bwrap parses+validates args as normal, writes a canonical plan to
BWRAP_DRYRUN_FD (default stdout), and exit(0) BEFORE any namespace/mount/exec.
"""
import sys, pathlib

src = pathlib.Path(sys.argv[1])
text = src.read_text()

DUMPER = r'''
/* ---- bwrap-rs shadow oracle (dry-run plan dump) -------------------------
   Additive, env-gated. When BWRAP_DRYRUN is set, bwrap parses and validates
   its arguments exactly as normal, then writes a canonical description of the
   resulting plan to the fd named by BWRAP_DRYRUN_FD (default stdout) and
   exit(0) BEFORE performing any namespace/mount/exec setup, so bwrap-rs can run
   the real C as a side-effect-free oracle. With the variable unset, nothing
   below runs and bwrap behaves identically. */
static const char * const dryrun_op_names[] = {
  "BIND_MOUNT", "RO_BIND_MOUNT", "DEV_BIND_MOUNT",
  "OVERLAY_MOUNT", "TMP_OVERLAY_MOUNT", "RO_OVERLAY_MOUNT", "OVERLAY_SRC",
  "MOUNT_PROC", "MOUNT_DEV", "MOUNT_TMPFS", "MOUNT_MQUEUE",
  "MAKE_DIR", "MAKE_FILE", "MAKE_BIND_FILE", "MAKE_RO_BIND_FILE",
  "MAKE_SYMLINK", "REMOUNT_RO_NO_RECURSIVE", "SET_HOSTNAME", "CHMOD",
};

static void
dryrun_dump_and_exit (void)
{
  SetupOp *op;
  int fd = 1;
  const char *fdenv = getenv ("BWRAP_DRYRUN_FD");
  if (fdenv != NULL && fdenv[0] != '\0')
    fd = atoi (fdenv);

  dprintf (fd, "bwrap-dryrun v1\n");
  dprintf (fd, "flag unshare_user=%d\n", opt_unshare_user ? 1 : 0);
  dprintf (fd, "flag unshare_pid=%d\n", opt_unshare_pid ? 1 : 0);
  dprintf (fd, "flag unshare_net=%d\n", opt_unshare_net ? 1 : 0);
  dprintf (fd, "flag unshare_ipc=%d\n", opt_unshare_ipc ? 1 : 0);
  dprintf (fd, "flag unshare_uts=%d\n", opt_unshare_uts ? 1 : 0);
  dprintf (fd, "flag unshare_cgroup=%d\n", opt_unshare_cgroup ? 1 : 0);
  dprintf (fd, "flag unshare_cgroup_try=%d\n", opt_unshare_cgroup_try ? 1 : 0);
  dprintf (fd, "flag disable_userns=%d\n", opt_disable_userns ? 1 : 0);
  dprintf (fd, "flag assert_userns_disabled=%d\n", opt_assert_userns_disabled ? 1 : 0);
  dprintf (fd, "flag as_pid_1=%d\n", opt_as_pid_1 ? 1 : 0);
  dprintf (fd, "flag new_session=%d\n", opt_new_session ? 1 : 0);
  dprintf (fd, "flag die_with_parent=%d\n", opt_die_with_parent ? 1 : 0);
  dprintf (fd, "uid %ld\n", (long) opt_sandbox_uid);
  dprintf (fd, "gid %ld\n", (long) opt_sandbox_gid);
  dprintf (fd, "hostname %s\n", opt_sandbox_hostname ? opt_sandbox_hostname : "-");
  dprintf (fd, "chdir %s\n", opt_chdir_path ? opt_chdir_path : "-");
  dprintf (fd, "argv0 %s\n", opt_argv0 ? opt_argv0 : "-");

  for (op = ops; op != NULL; op = op->next)
    {
      const char *name = (op->type >= 0 && op->type <= SETUP_CHMOD)
        ? dryrun_op_names[op->type] : "UNKNOWN";
      dprintf (fd, "op %s src=%s dest=%s fd=%d flags=%d perms=%d size=%zu\n",
               name,
               op->source ? op->source : "-",
               op->dest ? op->dest : "-",
               op->fd, (int) op->flags, op->perms, op->size);
    }
  dprintf (fd, "end\n");
  exit (0);
}
/* ------------------------------------------------------------------------ */

'''

# --- Edit 1: insert the dumper just before the SeccompProgram typedef ---
anchor1 = ("  lock->path = path;\n"
           "  return lock;\n"
           "}\n\n"
           "typedef struct _SeccompProgram SeccompProgram;")
repl1 = ("  lock->path = path;\n"
         "  return lock;\n"
         "}\n"
         + DUMPER +
         "typedef struct _SeccompProgram SeccompProgram;")
assert text.count(anchor1) == 1, f"anchor1 count = {text.count(anchor1)}"
text = text.replace(anchor1, repl1)

# --- Edit 2: insert the dry-run turn-off just before the /proc open ---
anchor2 = ('  if (opt_as_pid_1 && lock_files != NULL)\n'
           '    die ("Specifying --as-pid-1 and --lock-file is not permitted");\n')
repl2 = (anchor2 +
         '\n'
         '  /* bwrap-rs shadow oracle: dump the fully-parsed, validated plan and\n'
         '     exit before any effectful setup, when BWRAP_DRYRUN is set. */\n'
         '  {\n'
         '    const char *bwrap_rs_dryrun = getenv ("BWRAP_DRYRUN");\n'
         '    if (bwrap_rs_dryrun != NULL && bwrap_rs_dryrun[0] != \'\\0\')\n'
         '      dryrun_dump_and_exit ();\n'
         '  }\n')
assert text.count(anchor2) == 1, f"anchor2 count = {text.count(anchor2)}"
text = text.replace(anchor2, repl2)

src.write_text(text)
print("patched", src)
