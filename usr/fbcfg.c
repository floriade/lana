/*
 * Lightweight Autonomic Network Architecture
 *
 * Functional block userspace configuration tool for LANA.
 *
 * strlcpy taken from the Linux kernel.
 * Copyright 1991, 1992 Linus Torvalds <torvalds@linux-foundation.org>
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/if.h>

#include "xt_user.h"

#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef bug
# define bug() __builtin_trap()
#endif

#define PROGNAME "fbctl"
#define VERSNAME "0.9"

size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}

	return ret;
}

static inline void die(void)
{
	exit(EXIT_FAILURE);
}

static inline void panic(char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);

	die();
}

static inline void whine(char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);
}

void check_for_root_maybe_die(void)
{
	if (geteuid() != 0)
		panic("Uhhuh, not root?! \n");
}

static void usage(void)
{
	printf("\n%s %s\n", PROGNAME, VERSNAME);
	printf("Usage: %s <cmd> [<args> ...]\n", PROGNAME);
	printf("Commands:\n");
	printf("  preload <module>\n");
	printf("  add <name> <type>\n");
	printf("  set <name> <string>\n");
	printf("  rm <name>\n");
	printf("  bind <name1> <name2>\n");
	printf("  unbind <name1> <name2>\n");
	printf("\n");
	printf("Please report bugs to <dborkma@tik.ee.ethz.ch>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void version(void)
{
	printf("\n%s %s\n", PROGNAME, VERSNAME);
	printf("Please report bugs to <dborkma@tik.ee.ethz.ch>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void do_preload(int argc, char **argv)
{
	int ret, fd;
	char path[256], file[320], cmd[512], *env;
	struct stat sb;

	if (argc != 1)
		panic("Invalid args!\n");

	memset(cmd, 0, sizeof(cmd));
	env = getenv("FBCFG_PRELOAD_DIR");
	if (!env) {
		snprintf(cmd, sizeof(cmd), "modprobe %s", argv[0]);
		cmd[sizeof(cmd) - 1] = 0;
		ret = system(cmd);
		ret = WEXITSTATUS(ret);
		if (ret != 0)
			panic("Preload failed!\n");
		return;
	}

	memset(path, 0, sizeof(path));
	memcpy(path, env, sizeof(path));
	path[sizeof(path) - 1] = 0;
	memset(file, 0, sizeof(file));
	snprintf(file, sizeof(file), "%s%s.ko", path, argv[0]);
	file[sizeof(file) - 1] = 0;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		panic("Module does not exist!\n");
	ret = fstat(fd, &sb);
	if (ret < 0)
		panic("Cannot fstat file!\n");
	if (!S_ISREG (sb.st_mode))
		panic("Module is not a regular file!\n");
	if (sb.st_uid != geteuid())
		panic("Module is not owned by root! Someone could "
		      "compromise your system!\n");
	close(fd);

	snprintf(cmd, sizeof(cmd), "insmod %s", file);
	cmd[sizeof(cmd) - 1] = 0;
	ret = system(cmd);
	ret = WEXITSTATUS(ret);
	if (ret != 0)
		panic("Preload failed!\n");
}

static void do_add(int argc, char **argv)
{
}

static void do_set(int argc, char **argv)
{
}

static void do_rm(int argc, char **argv)
{
}

static void do_bind(int argc, char **argv)
{
}

static void do_unbind(int argc, char **argv)
{
}

int main(int argc, char **argv)
{
	check_for_root_maybe_die();

	if (argc <= 1)
		usage();
	argc--;	argv++;
	if (!strncmp("help", argv[0], strlen("help")))
		usage();
	else if (!strncmp("version", argv[0], strlen("version")))
		version();
	else if (!strncmp("preload", argv[0], strlen("preload")))
		do_preload(--argc, ++argv);
	else if (!strncmp("add", argv[0], strlen("add")))
		do_add(--argc, ++argv);
	else if (!strncmp("set", argv[0], strlen("set")))
		do_set(--argc, ++argv);
	else if (!strncmp("rm", argv[0], strlen("rm")))
		do_rm(--argc, ++argv);
	else if (!strncmp("bind", argv[0], strlen("bind")))
		do_bind(--argc, ++argv);
	else if (!strncmp("unbind", argv[0], strlen("unbind")))
		do_unbind(--argc, ++argv);
	else
		usage();
	return 0;
}
