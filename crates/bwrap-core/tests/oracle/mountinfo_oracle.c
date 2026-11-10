/* Differential-test oracle: verbatim copies of bubblewrap's parse_mountinfo()
 * and its helpers (LGPL-2.0-or-later, containers/bubblewrap, bind-mount.c +
 * utils.c), patched only to read the mountinfo text from a file argument
 * instead of /proc. Used by tests/mountinfo_oracle.rs to pin the Rust port. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/mount.h>

#define cleanup_free
#define cleanup_mount_tab
#define UNUSED

static char *g_mountinfo;

static void *xcalloc(size_t n, size_t s) { void *p = calloc(n, s); if (!p) abort(); return p; }
static char *xstrdup_(const char *s) { char *p = strdup(s); if (!p) abort(); return p; }
#define xstrdup xstrdup_
#define die(...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); exit(3); } while (0)
static void *steal_pointer_(void *pp) { void **p = (void **)pp; void *v = *p; *p = NULL; return v; }
#define steal_pointer(pp) steal_pointer_((pp))

typedef struct MountInfo MountInfo;
struct MountInfo { char *mountpoint; unsigned long options; };
typedef MountInfo *MountTab;

typedef struct MountInfoLine MountInfoLine;
struct MountInfoLine {
  const char *mountpoint;
  const char *options;
  bool covered;
  int id;
  int parent_id;
  MountInfoLine *first_child;
  MountInfoLine *next_sibling;
};

/* Compares if str has a specific path prefix. This differs
   from a regular prefix in two ways. First of all there may
   be multiple slashes separating the path elements, and
   secondly, if a prefix is matched that has to be en entire
   path element. For instance /a/prefix matches /a/prefix/foo/bar,
   but not /a/prefixfoo/bar. */
bool
has_path_prefix (const char *str,
                 const char *prefix)
{
  while (true)
    {
      /* Skip consecutive slashes to reach next path
         element */
      while (*str == '/')
        str++;
      while (*prefix == '/')
        prefix++;

      /* No more prefix path elements? Done! */
      if (*prefix == 0)
        return true;

      /* Compare path element */
      while (*prefix != 0 && *prefix != '/')
        {
          if (*str != *prefix)
            return false;
          str++;
          prefix++;
        }

      /* Matched prefix path element,
         must be entire str path element */
      if (*str != '/' && *str != 0)
        return false;
    }
}

bool
path_equal (const char *path1,
            const char *path2)
{
  while (true)
    {
      /* Skip consecutive slashes to reach next path
         element */
      while (*path1 == '/')
        path1++;
      while (*path2 == '/')
        path2++;

      /* No more prefix path elements? Done! */
      if (*path1 == 0 || *path2 == 0)
        return *path1 == 0 && *path2 == 0;

      /* Compare path element */
      while (*path1 != 0 && *path1 != '/')
        {
          if (*path1 != *path2)
            return false;
          path1++;
          path2++;
        }

      /* Matched path1 path element, must be entire path element */
      if (*path2 != '/' && *path2 != 0)
        return false;
    }
}

static char *
skip_token (char *line, bool eat_whitespace)
{
  while (*line != ' ' && *line != '\n')
    line++;

  if (eat_whitespace && *line == ' ')
    line++;

  return line;
}

static char *
unescape_inline (char *escaped)
{
  char *unescaped, *res;
  const char *end;

  res = escaped;
  end = escaped + strlen (escaped);

  unescaped = escaped;
  while (escaped < end)
    {
      if (*escaped == '\\')
        {
          *unescaped++ =
            ((escaped[1] - '0') << 6) |
            ((escaped[2] - '0') << 3) |
            ((escaped[3] - '0') << 0);
          escaped += 4;
        }
      else
        {
          *unescaped++ = *escaped++;
        }
    }
  *unescaped = 0;
  return res;
}

static bool
match_token (const char *token, const char *token_end, const char *str)
{
  while (token != token_end && *token == *str)
    {
      token++;
      str++;
    }
  if (token == token_end)
    return *str == 0;

  return false;
}

static unsigned long
decode_mountoptions (const char *options)
{
  const char *token, *end_token;
  int i;
  unsigned long flags = 0;
  static const struct  { int   flag;
                         const char *name;
  } flags_data[] = {
    { 0, "rw" },
    { MS_RDONLY, "ro" },
    { MS_NOSUID, "nosuid" },
    { MS_NODEV, "nodev" },
    { MS_NOEXEC, "noexec" },
    { MS_NOATIME, "noatime" },
    { MS_NODIRATIME, "nodiratime" },
    { MS_RELATIME, "relatime" },
    { 0, NULL }
  };

  token = options;
  do
    {
      end_token = strchr (token, ',');
      if (end_token == NULL)
        end_token = token + strlen (token);

      for (i = 0; flags_data[i].name != NULL; i++)
        {
          if (match_token (token, end_token, flags_data[i].name))
            {
              flags |= flags_data[i].flag;
              break;
            }
        }

      if (*end_token != 0)
        token = end_token + 1;
      else
        token = NULL;
    }
  while (token != NULL);

  return flags;
}

static void
mount_tab_free (MountTab tab)
{
  int i;

  for (i = 0; tab[i].mountpoint != NULL; i++)
    free (tab[i].mountpoint);
  free (tab);
}

static unsigned int
count_lines (const char *data)
{
  unsigned int count = 0;
  const char *p = data;

  while (*p != 0)
    {
      if (*p == '\n')
        count++;
      p++;
    }

  /* If missing final newline, add one */
  if (p > data && *(p-1) != '\n')
    count++;

  return count;
}

static int
count_mounts (MountInfoLine *line)
{
  MountInfoLine *child;
  int res = 0;

  if (!line->covered)
    res += 1;

  child = line->first_child;
  while (child != NULL)
    {
      res += count_mounts (child);
      child = child->next_sibling;
    }

  return res;
}

static MountInfo *
collect_mounts (MountInfo *info, MountInfoLine *line)
{
  MountInfoLine *child;

  if (!line->covered)
    {
      info->mountpoint = xstrdup (line->mountpoint);
      info->options = decode_mountoptions (line->options);
      info ++;
    }

  child = line->first_child;
  while (child != NULL)
    {
      info = collect_mounts (info, child);
      child = child->next_sibling;
    }

  return info;
}

static MountTab
parse_mountinfo (const char *root_mount)
{
  cleanup_free char *mountinfo = NULL;
  cleanup_free MountInfoLine *lines = NULL;
  cleanup_free MountInfoLine **by_id = NULL;
  cleanup_mount_tab MountTab mount_tab = NULL;
  MountInfo *end_tab;
  int n_mounts;
  char *line;
  unsigned int i;
  int max_id;
  unsigned int n_lines;
  int root;

  mountinfo = strdup (g_mountinfo);
  if (mountinfo == NULL)
    { fprintf(stderr, "no mountinfo\n"); exit(2); }

  n_lines = count_lines (mountinfo);
  lines = xcalloc (n_lines, sizeof (MountInfoLine));

  max_id = 0;
  line = mountinfo;
  i = 0;
  root = -1;
  while (*line != 0)
    {
      int rc, consumed = 0;
      unsigned int maj, min;
      char *end;
      char *rest;
      char *mountpoint;
      char *mountpoint_end;
      char *options;
      char *options_end;
      char *next_line;

      assert (i < n_lines);

      end = strchr (line, '\n');
      if (end != NULL)
        {
          *end = 0;
          next_line = end + 1;
        }
      else
        next_line = line + strlen (line);

      rc = sscanf (line, "%d %d %u:%u %n", &lines[i].id, &lines[i].parent_id, &maj, &min, &consumed);
      if (rc != 4)
        die ("Can't parse mountinfo line");
      rest = line + consumed;

      rest = skip_token (rest, true); /* mountroot */
      mountpoint = rest;
      rest = skip_token (rest, false); /* mountpoint */
      mountpoint_end = rest++;
      options = rest;
      rest = skip_token (rest, false); /* vfs options */
      options_end = rest;

      *mountpoint_end = 0;
      lines[i].mountpoint = unescape_inline (mountpoint);

      *options_end = 0;
      lines[i].options = options;

      if (lines[i].id > max_id)
        max_id = lines[i].id;
      if (lines[i].parent_id > max_id)
        max_id = lines[i].parent_id;

      if (path_equal (lines[i].mountpoint, root_mount))
        root = i;

      i++;
      line = next_line;
    }
  assert (i == n_lines);

  if (root == -1)
    {
      mount_tab = xcalloc (1, sizeof (MountInfo));
      return steal_pointer (&mount_tab);
    }

  by_id = xcalloc (max_id + 1, sizeof (MountInfoLine*));
  for (i = 0; i < n_lines; i++)
    by_id[lines[i].id] = &lines[i];

  for (i = 0; i < n_lines; i++)
    {
      MountInfoLine *this = &lines[i];
      MountInfoLine *parent = by_id[this->parent_id];
      MountInfoLine **to_sibling;
      MountInfoLine *sibling;
      bool covered = false;

      if (!has_path_prefix (this->mountpoint, root_mount))
        continue;

      if (parent == NULL)
        continue;

      if (strcmp (parent->mountpoint, this->mountpoint) == 0)
        parent->covered = true;

      to_sibling = &parent->first_child;
      sibling = parent->first_child;
      while (sibling != NULL)
        {
          /* If this mountpoint is a path prefix of the sibling,
           * say this->mp=/foo/bar and sibling->mp=/foo, then it is
           * covered by the sibling, and we drop it. */
          if (has_path_prefix (this->mountpoint, sibling->mountpoint))
            {
              covered = true;
              break;
            }

          /* If the sibling is a path prefix of this mount point,
           * say this->mp=/foo and sibling->mp=/foo/bar, then the sibling
           * is covered, and we drop it.
            */
          if (has_path_prefix (sibling->mountpoint, this->mountpoint))
            *to_sibling = sibling->next_sibling;
          else
            to_sibling = &sibling->next_sibling;
          sibling = sibling->next_sibling;
        }

      if (covered)
          continue;

      *to_sibling = this;
    }

  n_mounts = count_mounts (&lines[root]);
  mount_tab = xcalloc (n_mounts + 1, sizeof (MountInfo));

  end_tab = collect_mounts (&mount_tab[0], &lines[root]);
  assert (end_tab == &mount_tab[n_mounts]);

  return steal_pointer (&mount_tab);
}
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: oracle MOUNTINFO_FILE ROOT\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    g_mountinfo = xcalloc(n + 1, 1);
    if (n > 0 && fread(g_mountinfo, 1, n, f) != (size_t)n) { return 2; }
    fclose(f);
    MountTab tab = parse_mountinfo(argv[2]);
    for (int i = 0; tab[i].mountpoint != NULL; i++)
        printf("%s %lu\n", tab[i].mountpoint, tab[i].options);
    return 0;
}
