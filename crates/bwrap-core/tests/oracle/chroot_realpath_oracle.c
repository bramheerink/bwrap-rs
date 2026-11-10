/* Differential-test oracle: a verbatim copy of bubblewrap's chroot_realpath()
 * (LGPL-2.0-or-later, containers/bubblewrap, chroot_realpath.c) plus a small
 * main() that resolves argv[2] within argv[1] and prints the result. Used only
 * by tests/chroot_realpath_oracle.rs to pin the Rust port's behaviour. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#ifndef __set_errno
#define __set_errno(val) ((errno) = (val))
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define MAX_READLINKS 32

char *chroot_realpath(const char *chroot, const char *path, char resolved_path[])
{
	char copy_path[PATH_MAX];
	char link_path[PATH_MAX];
	char got_path[PATH_MAX];
	char *got_path_root = got_path;
	char *new_path = got_path;
	char *max_path;
	int readlinks = 0;
	int n;
	int chroot_len;
	int last_component;

	/* Trivial case. */
	if (chroot == NULL || *chroot == '\0' ||
	    (*chroot == '/' && chroot[1] == '\0')) {
		if (strlen(path) >= PATH_MAX) {
			__set_errno(ENAMETOOLONG);
			return NULL;
		}
		strcpy(resolved_path, path);
		return resolved_path;
	}

	chroot_len = strlen(chroot);

	if (chroot_len + strlen(path) >= PATH_MAX - 3) {
		__set_errno(ENAMETOOLONG);
		return NULL;
	}

	/* Make a copy of the source path since we may need to modify it. */
	strcpy(copy_path, path);
	path = copy_path;
	max_path = copy_path + PATH_MAX - chroot_len - 3;

	/* Start with the chroot path. */
	strcpy(new_path, chroot);
	new_path += chroot_len;
	while (*new_path == '/' && new_path > got_path)
		new_path--;
	got_path_root = new_path;
	*new_path++ = '/';

	/* Expand each slash-separated pathname component. */
	while (*path != '\0') {
		/* Ignore stray "/". */
		if (*path == '/') {
			path++;
			continue;
		}
		if (*path == '.') {
			/* Ignore ".". */
			if (path[1] == '\0' || path[1] == '/') {
				path++;
				continue;
			}
			if (path[1] == '.') {
				if (path[2] == '\0' || path[2] == '/') {
					path += 2;
					/* Ignore ".." at root. */
					if (new_path == got_path_root + 1)
						continue;
					/* Handle ".." by backing up. */
					while ((--new_path)[-1] != '/');
					continue;
				}
			}
		}
		/* Safely copy the next pathname component. */
		while (*path != '\0' && *path != '/') {
			if (path > max_path || new_path >= got_path + PATH_MAX - 1) {
				__set_errno(ENAMETOOLONG);
				return NULL;
			}
			*new_path++ = *path++;
		}

		last_component = (*path == '\0');

#ifdef S_IFLNK
		/* Protect against infinite loops. */
		if (readlinks++ > MAX_READLINKS) {
			__set_errno(ELOOP);
			return NULL;
		}
		/* See if latest pathname component is a symlink. */
		*new_path = '\0';
		n = readlink(got_path, link_path, PATH_MAX - 1);
		if (n < 0) {
			/* If a component doesn't exist, then return what we could translate. */
			if (errno == ENOENT) {
				int ret = snprintf (resolved_path, PATH_MAX, "%s%s%s", got_path, path[0] == '/' || path[0] == '\0' ? "" : "/", path);
				if (ret >= PATH_MAX) {
					__set_errno(ENAMETOOLONG);
					return NULL;
				}
				return resolved_path;
			}
			/* EINVAL means the file exists but isn't a symlink. */
			if (errno != EINVAL)
				return NULL;
		} else {
			/* Note: readlink doesn't add the null byte. */
			link_path[n] = '\0';
			if (*link_path == '/') {
				/* Start over for an absolute symlink. */
				new_path = got_path_root;
				*new_path++ = '/';
			}
			else {
				/* Otherwise back up over this component, keeping the
				   separator, so that the expanded symlink is not
				   concatenated to the parent directory name. */
				while (*(--new_path) != '/');
				new_path++;
			}
			/* Safe sex check. */
			if (strlen(path) + n >= PATH_MAX - 2) {
				__set_errno(ENAMETOOLONG);
				return NULL;
			}
			/* Insert symlink contents into path. */
			strcat(link_path, path);
			strcpy(copy_path, link_path);
			path = copy_path;
		}
#endif							/* S_IFLNK */
		if (!last_component) {
			if (new_path >= got_path + PATH_MAX - 1) {
				__set_errno(ENAMETOOLONG);
				return NULL;
			}
			*new_path++ = '/';
		}
	}
	/* Delete trailing slash but don't whomp a lone slash. */
	if (new_path != got_path + 1 && new_path[-1] == '/')
		new_path--;
	/* Make sure it's null terminated. */
	*new_path = '\0';
	strcpy(resolved_path, got_path);
	return resolved_path;
}

int main(int argc, char **argv) {
    char resolved[PATH_MAX];
    if (argc != 3) { fprintf(stderr, "usage: oracle CHROOT PATH\n"); return 2; }
    errno = 0;
    char *r = chroot_realpath(argv[1], argv[2], resolved);
    if (r == NULL) { printf("ERR:%d\n", errno); return 0; }
    printf("OK:%s\n", r);
    return 0;
}
