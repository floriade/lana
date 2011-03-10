/*
 * pstat - Linux performance counter subsystem uspace or kthread tracing
 *
 * Borrowed some code from libperf, which has been written by
 * Copyright 2010 Wolfgang Richter <wolf@cs.cmu.edu>
 * Copyright 2010 Ekaterina Taralova <etaralova@cs.cmu.edu>
 * Copyright 2010 Karl Naden <kbn@cs.cmu.edu>
 * Subject to the GPL.
 *
 * Performance events, data type definitions, declarations by
 * Copyright 2008-2009 Thomas Gleixner <tglx@linutronix.de>
 * Copyright 2008-2009 Ingo Molnar <mingo@redhat.com>
 * Copyright 2008-2009 Peter Zijlstra <pzijlstr@redhat.com>
 * Copyright 2009      Paul Mackerras <paulus@au1.ibm.com>
 * Subject to the GPL / see COPYING.
 *
 * pstat has been written by
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 *
 * Needs Linux kernel >= 2.6.32. For more detailed information have a look at 
 * tools/perf/design.txt and http://lkml.org/lkml/2009/6/6/149. Tested on 
 * x86_64. Larger comments refer to tools/perf/design.txt. Be warned, the stuff
 * from design.txt, especially data structures are heavily deprecated!
 *
 * Compile: gcc pstat.c -o pstat -lrt -O2
 * Patches are welcome! Mail them to <dborkma@tik.ee.ethz.ch>.
 *  - Additions made by Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * Not yet working:
 *  - Tracing another already running pid not yet working! CPU goes up
 *    to 100% and the program never returns.
 *  - Tracing a single event returns in strange numbers! May be because
 *    of group leader settings?
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * Attribute type
 */
enum perf_type_id {
	PERF_TYPE_HARDWARE = 0,
	PERF_TYPE_SOFTWARE = 1,
	PERF_TYPE_TRACEPOINT = 2,
	PERF_TYPE_HW_CACHE = 3,
	PERF_TYPE_RAW = 4,
	PERF_TYPE_BREAKPOINT = 5,
	PERF_TYPE_MAX, /* non-ABI */
};

/*
 * Generalized performance event event_id types, used by the 
 * attr.event_id parameter of the sys_perf_event_open() syscall:
 */
enum perf_hw_id {
	PERF_COUNT_HW_CPU_CYCLES = 0,
	PERF_COUNT_HW_INSTRUCTIONS = 1,
	PERF_COUNT_HW_CACHE_REFERENCES = 2,
	PERF_COUNT_HW_CACHE_MISSES = 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4,
	PERF_COUNT_HW_BRANCH_MISSES = 5,
	PERF_COUNT_HW_BUS_CYCLES = 6,
	PERF_COUNT_HW_MAX, /* non-ABI */
};

/*
 * Generalized hardware cache events:
 * { L1-D, L1-I, LLC, ITLB, DTLB, BPU } x
 * { read, write, prefetch } x
 * { accesses, misses }
 */
enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D = 0,
	PERF_COUNT_HW_CACHE_L1I = 1,
	PERF_COUNT_HW_CACHE_LL = 2,
	PERF_COUNT_HW_CACHE_DTLB = 3,
	PERF_COUNT_HW_CACHE_ITLB = 4,
	PERF_COUNT_HW_CACHE_BPU = 5,
	PERF_COUNT_HW_CACHE_MAX, /* non-ABI */
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ = 0,
	PERF_COUNT_HW_CACHE_OP_WRITE = 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH = 2,
	PERF_COUNT_HW_CACHE_OP_MAX, /* non-ABI */
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS = 1,
	PERF_COUNT_HW_CACHE_RESULT_MAX, /* non-ABI */
};

/*
 * Special "software" events provided by the kernel, even if the hardware
 * does not support performance events. These events measure various
 * physical and sw events of the kernel (and allow the profiling of them as
 * well):
 */
enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK = 0,
	PERF_COUNT_SW_TASK_CLOCK = 1,
	PERF_COUNT_SW_PAGE_FAULTS = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
	PERF_COUNT_SW_EMULATION_FAULTS = 8,
	PERF_COUNT_SW_MAX, /* non-ABI */
};

/*
 * Hardware event_id to monitor via a performance monitoring event:
 *
 * The 'disabled' bit specifies whether the counter starts out disabled
 * or enabled.  If it is initially disabled, it can be enabled by ioctl
 * or prctl.
 * 
 * The 'inherit' bit, if set, specifies that this counter should count
 * events on descendant tasks as well as the task specified.  This only
 * applies to new descendents, not to any existing descendents at the
 * time the counter is created (nor to any new descendents of existing
 * descendents).
 * 
 * The 'pinned' bit, if set, specifies that the counter should always be
 * on the CPU if at all possible.  It only applies to hardware counters
 * and only to group leaders.  If a pinned counter cannot be put onto the
 * CPU (e.g. because there are not enough hardware counters or because of
 * a conflict with some other event), then the counter goes into an
 * 'error' state, where reads return end-of-file (i.e. read() returns 0)
 * until the counter is subsequently enabled or disabled.
 * 
 * The 'exclusive' bit, if set, specifies that when this counter's group
 * is on the CPU, it should be the only group using the CPU's counters.
 * In future, this will allow sophisticated monitoring programs to supply
 * extra configuration information via 'extra_config_len' to exploit
 * advanced features of the CPU's Performance Monitor Unit (PMU) that are
 * not otherwise accessible and that might disrupt other hardware
 * counters.
 * 
 * The 'exclude_user', 'exclude_kernel' and 'exclude_hv' bits provide a
 * way to request that counting of events be restricted to times when the
 * CPU is in user, kernel and/or hypervisor mode.
 */
struct perf_event_attr {
	/*
	 * Major type: hardware/software/tracepoint/etc.
	 */
	__u32 type;
	/*
	 * Size of the attr structure, for fwd/bwd compat.
	*/
	__u32 size;
	/*
	 * Type specific configuration information.
	 */
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 disabled:1, /* off by default */
	      inherit:1, /* children inherit it */
	      pinned:1, /* must always be on PMU */
	      exclusive:1, /* only group on PMU */
	      exclude_user:1, /* don't count user */
	      exclude_kernel:1, /* ditto kernel */
	      exclude_hv:1, /* ditto hypervisor */
	      exclude_idle:1, /* don't count when idle */
	      mmap:1, /* include mmap data */
	      comm:1, /* include comm data */
	      freq:1, /* use freq, not period */
	      inherit_stat:1, /* per task counts */
	      enable_on_exec:1, /* next exec enables */
	      task:1, /* trace fork/exit */
	      watermark:1, /* wakeup_watermark */
	      precise_ip:2, /* skid constraint */
	      mmap_data:1, /* non-exec mmap data */
	      __reserved_1:46;
	union {
		__u32 wakeup_events; /* wakeup every n events */
		__u32 wakeup_watermark; /* bytes before wakeup */
	};
	__u32 bp_type;
	__u64 bp_addr;
	__u64 bp_len;
};

enum perf_event_ioc_flags {
	PERF_IOC_FLAG_GROUP = 1U << 0,
};

/*
 * Ioctls that can be done on a perf event fd:
 */
#define PERF_EVENT_IOC_ENABLE _IO ('$', 0)
#define PERF_EVENT_IOC_DISABLE _IO ('$', 1)
#define PERF_EVENT_IOC_REFRESH _IO ('$', 2)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define MAX_COUNTERS 32

#define FDS_INVALID  -1
#define GRP_INVALID  -1

#define MODE_KERNEL 1
#define MODE_USER   2
#define MODE_HYPER  4
#define MODE_IDLE   8

#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef bug
# define bug() __builtin_trap()
#endif

#define PROGNAME "pstat"
#define VERSNAME "0.9"

/*
 * Constants
 */
enum tracepoint {
	/* Software tracepoints */
	COUNT_SW_CPU_CLOCK = 0,
	COUNT_SW_TASK_CLOCK = 1,
	COUNT_SW_CONTEXT_SWITCHES = 2,
	COUNT_SW_CPU_MIGRATIONS = 3,
	COUNT_SW_PAGE_FAULTS = 4,
	COUNT_SW_PAGE_FAULTS_MIN = 5,
	COUNT_SW_PAGE_FAULTS_MAJ = 6,
	/* Hardware counters */
	COUNT_HW_CPU_CYCLES = 7,
	COUNT_HW_INSTRUCTIONS = 8,
	COUNT_HW_CACHE_REFERENCES = 9,
	COUNT_HW_CACHE_MISSES = 10,
	COUNT_HW_BRANCH_INSTRUCTIONS = 11,
	COUNT_HW_BRANCH_MISSES = 12,
	COUNT_HW_BUS_CYCLES = 13,
	/* Cache counters */
	/* L1D - data cache */
	COUNT_HW_CACHE_L1D_LOADS = 14,
	COUNT_HW_CACHE_L1D_LOADS_MISSES = 15,
	COUNT_HW_CACHE_L1D_STORES = 16,
	COUNT_HW_CACHE_L1D_STORES_MISSES = 17,
	COUNT_HW_CACHE_L1D_PREFETCHES = 18,
	/* L1I - Instruction cache */
	COUNT_HW_CACHE_L1I_LOADS = 19,
	COUNT_HW_CACHE_L1I_LOADS_MISSES = 20,
	/* LL - Last level cache */
	COUNT_HW_CACHE_LL_LOADS = 21,
	COUNT_HW_CACHE_LL_LOADS_MISSES = 22,
	COUNT_HW_CACHE_LL_STORES = 23,
	COUNT_HW_CACHE_LL_STORES_MISSES = 24,
	/* DTLB - Data translation lookaside buffer */
	COUNT_HW_CACHE_DTLB_LOADS = 25,
	COUNT_HW_CACHE_DTLB_LOADS_MISSES = 26,
	COUNT_HW_CACHE_DTLB_STORES = 27,
	COUNT_HW_CACHE_DTLB_STORES_MISSES = 28,
	/* ITLB - Instructiont translation lookaside buffer */
	COUNT_HW_CACHE_ITLB_LOADS = 29,
	COUNT_HW_CACHE_ITLB_LOADS_MISSES = 30,
	/* BPU - Branch prediction unit */
	COUNT_HW_CACHE_BPU_LOADS = 31,
	COUNT_HW_CACHE_BPU_LOADS_MISSES = 32,
	/* Internal */
	INTERNAL_SW_WALL_TIME = 33,
	INTERNAL_INVALID_TP = 34
};

struct trace_map {
	char *name;
	/* char *description; */
	enum tracepoint tracepoint;
};

#define TRACE_MAP_SET(x)	\
{				\
	.name = #x,		\
	.tracepoint = x		\
}

struct trace_map whole_map[] = {
	TRACE_MAP_SET(COUNT_SW_CPU_CLOCK),
	TRACE_MAP_SET(COUNT_SW_TASK_CLOCK),
	TRACE_MAP_SET(COUNT_SW_CONTEXT_SWITCHES),
	TRACE_MAP_SET(COUNT_SW_CPU_MIGRATIONS),
	TRACE_MAP_SET(COUNT_SW_PAGE_FAULTS),
	TRACE_MAP_SET(COUNT_SW_PAGE_FAULTS_MIN),
	TRACE_MAP_SET(COUNT_SW_PAGE_FAULTS_MAJ),
	TRACE_MAP_SET(COUNT_HW_CPU_CYCLES),
	TRACE_MAP_SET(COUNT_HW_INSTRUCTIONS),
	TRACE_MAP_SET(COUNT_HW_CACHE_REFERENCES),
	TRACE_MAP_SET(COUNT_HW_CACHE_MISSES),
	TRACE_MAP_SET(COUNT_HW_BRANCH_INSTRUCTIONS),
	TRACE_MAP_SET(COUNT_HW_BRANCH_MISSES),
	TRACE_MAP_SET(COUNT_HW_BUS_CYCLES),
	TRACE_MAP_SET(COUNT_HW_CACHE_L1D_LOADS),
	TRACE_MAP_SET(COUNT_HW_CACHE_L1D_LOADS_MISSES),
	TRACE_MAP_SET(COUNT_HW_CACHE_L1D_STORES),
	TRACE_MAP_SET(COUNT_HW_CACHE_L1D_STORES_MISSES),
	TRACE_MAP_SET(COUNT_HW_CACHE_L1D_PREFETCHES),
	TRACE_MAP_SET(COUNT_HW_CACHE_L1I_LOADS),
	TRACE_MAP_SET(COUNT_HW_CACHE_L1I_LOADS_MISSES),
	TRACE_MAP_SET(COUNT_HW_CACHE_LL_LOADS),
	TRACE_MAP_SET(COUNT_HW_CACHE_LL_LOADS_MISSES),
	TRACE_MAP_SET(COUNT_HW_CACHE_LL_STORES),
	TRACE_MAP_SET(COUNT_HW_CACHE_LL_STORES_MISSES),
	TRACE_MAP_SET(COUNT_HW_CACHE_ITLB_LOADS),
	TRACE_MAP_SET(COUNT_HW_CACHE_ITLB_LOADS_MISSES),
	TRACE_MAP_SET(COUNT_HW_CACHE_BPU_LOADS),
	TRACE_MAP_SET(COUNT_HW_CACHE_BPU_LOADS_MISSES),
	TRACE_MAP_SET(INTERNAL_SW_WALL_TIME),
	TRACE_MAP_SET(INTERNAL_INVALID_TP)
};

static struct perf_event_attr default_attrs[] = {
	{ /* Software attributes */
		.type = PERF_TYPE_SOFTWARE, 
		.config = PERF_COUNT_SW_CPU_CLOCK
	}, {
		.type = PERF_TYPE_SOFTWARE, 
		.config = PERF_COUNT_SW_TASK_CLOCK
	}, {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CONTEXT_SWITCHES
	}, {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_MIGRATIONS
	}, {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_PAGE_FAULTS
	}, {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_PAGE_FAULTS_MIN
	}, {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_PAGE_FAULTS_MAJ
	}, { /* Hardware attributes */
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES
	}, {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_INSTRUCTIONS
	}, {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CACHE_REFERENCES
	}, {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CACHE_MISSES
	}, {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS
	}, {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_BRANCH_MISSES
	}, {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_BUS_CYCLES
	}, { /* Caching attributes */
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_L1D           <<  0) | 
			   (PERF_COUNT_HW_CACHE_OP_READ       <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_L1D         <<  0) | 
			   (PERF_COUNT_HW_CACHE_OP_READ     <<  8) | 
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_L1D           <<  0) | 
			   (PERF_COUNT_HW_CACHE_OP_WRITE      <<  8) | 
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_L1D         <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_WRITE    <<  8) | 
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_L1D        <<  0) |
			(PERF_COUNT_HW_CACHE_OP_PREFETCH   <<  8) | 
			(PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_L1I           <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ       <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_L1I         <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ     <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_LL            <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ       <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_LL          <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ     <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_LL            <<  0) | 
			   (PERF_COUNT_HW_CACHE_OP_WRITE      <<  8) | 
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_LL          <<  0) | 
			   (PERF_COUNT_HW_CACHE_OP_WRITE    <<  8) | 
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_DTLB          <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ       <<  8) | 
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_DTLB        <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ     <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_DTLB          <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_WRITE      <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_DTLB        <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_WRITE    <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_ITLB          <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ       <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_ITLB        <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ     <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_BPU           <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ       <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16))
	}, {
		.type = PERF_TYPE_HW_CACHE,
		.config = ((PERF_COUNT_HW_CACHE_BPU         <<  0) |
			   (PERF_COUNT_HW_CACHE_OP_READ     <<  8) |
			   (PERF_COUNT_HW_CACHE_RESULT_MISS << 16))
	},
};

extern int optind;

static sig_atomic_t sigint = 0;

static const char *short_options = "p:c:ekuyvhlx:i";

static struct option long_options[] = {
	{"pid", required_argument, 0, 'p'},
	{"cpu", required_argument, 0, 'c'},
	{"use", required_argument, 0, 'x'},
	{"excl", no_argument, 0, 'e'},
	{"kernel", no_argument, 0, 'k'},
	{"user", no_argument, 0, 'u'},
	{"hyper", no_argument, 0, 'y'},
	{"idle", no_argument, 0, 'i'},
	{"list", no_argument, 0, 'l'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

struct perf_data {
	pid_t pid;
	int cpu;
	int group;
	int fds[MAX_COUNTERS];
	struct perf_event_attr *attrs;
	unsigned long long wall_start;
};

static inline void die(void)
{
	exit(EXIT_FAILURE);
}

static void usage(void)
{
	printf("\n%s %s\n", PROGNAME, VERSNAME);
	printf("Usage: %s [options] [<cmd>]\n", PROGNAME);
	printf("Options:\n");
	printf("  -p|--pid <pid>   Attach to running process/kthread\n");
	printf("  -c|--cpu <cpu>   Bind counter to cpuid\n");
	printf("  -e|--excl        Be exclusive counter group on CPU\n");
	printf("  -k|--kernel      Count events in kernel mode\n");
	printf("  -u|--user        Count events in user mode\n");
	printf("  -y|--hyper       Count events in hypervisor mode\n");
	printf("  -i|--idle        Do also count when idle\n");
	printf("  -l|--list        List possible events\n");
	printf("  -x|--use <event> Count only a certain event\n");
	printf("  -v|--version     Print version\n");
	printf("  -h|--help        Print this help\n");
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

static void reaper(int sig)
{
	int pid, status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		;
}

static void intr(int sig)
{
	sigint = 1;
}

static inline void register_signal(int signal, void (*handler)(int))
{
	sigset_t block_mask;
	struct sigaction saction;

	sigfillset(&block_mask);
	saction.sa_handler = handler;
	saction.sa_mask = block_mask;
	saction.sa_flags = SA_RESTART;

	sigaction(signal, &saction, NULL);
}

static inline unsigned long long rdclock(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
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

static void *xzmalloc(size_t size)
{
	void *ptr;

	if (unlikely(size == 0))
		panic("xzmalloc: zero size\n");

	ptr = malloc(size);
	if (unlikely(ptr == NULL))
		panic("xzmalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) size);
	memset(ptr, 0, size);

	return ptr;
}

static void xfree(void *ptr)
{
	if (unlikely(ptr == NULL))
		panic("xfree: NULL pointer given as argument\n");
	free(ptr);
}

/*
 * The 'group_fd' parameter allows counter "groups" to be set up.  A
 * counter group has one counter which is the group "leader".  The leader
 * is created first, with group_fd = -1 in the perf_event_open call
 * that creates it.  The rest of the group members are created
 * subsequently, with group_fd giving the fd of the group leader.
 * (A single counter on its own is created with group_fd = -1 and is
 * considered to be a group with only 1 member.)
 *
 * A counter group is scheduled onto the CPU as a unit, that is, it will
 * only be put onto the CPU if all of the counters in the group can be
 * put onto the CPU.  This means that the values of the member counters
 * can be meaningfully compared, added, divided (to get ratios), etc.,
 * with each other, since they have counted events for the same set of
 * executed instructions.
 */
static inline int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid,
				      int cpu, int group_fd,
				      unsigned long flags)
{
	/*
	 * PID settings:
	 *   pid == 0: counter attached to current task
	 *   pid > 0: counter attached to specific task
	 *   pid < 0: counter attached to all tasks
	 * CPU settings:
	 *   cpu >= 0: counter restricted to a specific CPU
	 *   cpu == -1: counter counts on all CPUs
	 * User/kernel/hypervisor modes:
	 *   See attr bits for excluding stuff!
	 * Note: pid == -1 && cpu == -1 is invalid!
	 * flags must be 0!
	 */
	attr->size = sizeof(*attr);
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static inline pid_t gettid()
{
	return syscall(SYS_gettid);
}

static struct perf_data *initialize(pid_t pid, int cpu, int mode, int excl)
{
	int i;
	struct perf_data *pd;
	struct perf_event_attr *attr;
	struct perf_event_attr *attrs;

	pd = xzmalloc(sizeof(*pd));
	if (pid < 0)
		pid = gettid();
	pd->group = GRP_INVALID;
	for (i = 0; i < ARRAY_SIZE(pd->fds); i++)
		pd->fds[i] = FDS_INVALID;
	pd->pid = pid;
	pd->cpu = cpu;

	attrs = xzmalloc(sizeof(*attrs) * ARRAY_SIZE(default_attrs));
	memcpy(attrs, default_attrs, sizeof(default_attrs));
	pd->attrs = attrs;

	for (i = 0; i < ARRAY_SIZE(default_attrs); i++) {
		attr = &attrs[i];

		attr->inherit = 1;
		attr->disabled = 1;
		attr->enable_on_exec = 0;
		attr->exclusive = excl;
		attr->exclude_user = ((mode & MODE_USER) == 0);
		attr->exclude_kernel = ((mode & MODE_KERNEL) == 0);
		attr->exclude_hv = ((mode & MODE_HYPER) == 0);
		attr->exclude_idle = ((mode & MODE_IDLE) == 0);
		/* pd->fds[0] is counter group leader! */
		pd->fds[i] = sys_perf_event_open(attr, pid, cpu,
						 i == 0 ? GRP_INVALID : pd->fds[0],
						 PERF_IOC_FLAG_GROUP);
		if (unlikely(pd->fds[i] < 0))
			panic("sys_perf_event_open failed: %s\n", strerror(errno));
	}

	pd->group = pd->fds[0];
	return pd;
}

/*
 * A read() on a counter returns the current value of the counter and possible
 * additional values as specified by 'read_format', each value is a u64 (8 bytes)
 * in size.
 */
static uint64_t read_counter(struct perf_data *pd, int counter)
{
	int ret;
	uint64_t value;

	if (counter == INTERNAL_SW_WALL_TIME)
		return (uint64_t) (rdclock() - pd->wall_start);
	if (unlikely(counter < 0 || counter > MAX_COUNTERS))
		panic("bug! invalid counter value!\n");

	ret = read(pd->fds[counter], &value, sizeof(uint64_t));
	if (unlikely(ret != sizeof(uint64_t)))
		panic("perf_counter read error!\n");

	return value;
}

/*
 * Counters can be enabled and disabled in two ways: via ioctl and via
 * prctl.  When a counter is disabled, it doesn't count or generate
 * events but does continue to exist and maintain its count value.
 *
 * Enabling or disabling the leader of a group enables or disables the
 * whole group; that is, while the group leader is disabled, none of the
 * counters in the group will count.  Enabling or disabling a member of a
 * group other than the leader only affects that counter - disabling an
 * non-leader stops that counter from counting but doesn't affect any
 * other counter.
 */
static void enable_counter(struct perf_data *pd, int counter)
{
	int ret;

	if (unlikely(counter < 0 || counter >= MAX_COUNTERS))
		panic("bug! invalid counter value!\n");
	if (pd->fds[counter] == FDS_INVALID) {
		pd->fds[counter] = sys_perf_event_open(&pd->attrs[counter],
						       pd->pid,pd->cpu,
						       pd->group,
						       PERF_IOC_FLAG_GROUP);
		if (unlikely(pd->fds[counter] < 0))
			panic("sys_perf_event_open failed!\n");
	}

	ret = ioctl(pd->fds[counter], PERF_EVENT_IOC_ENABLE);
	if (ret)
		panic("error enabling perf counter!\n");

	pd->wall_start = rdclock();
}

static void enable_all_counter(struct perf_data *pd)
{
	int ret, i;

	for (i = 0; i < MAX_COUNTERS; i++) {
		enable_counter(pd, i);
	}

	/* XXX: Only group leader? */
#if 0
	for (i = 0; i < MAX_COUNTERS; i++) {
		/* ret = ioctl(pd->group, PERF_EVENT_IOC_ENABLE); */
		ret = ioctl(pd->fds[i], PERF_EVENT_IOC_ENABLE);
		if (ret)
			panic("error enabling perf counter!\n");
	}
#endif
	pd->wall_start = rdclock();
}

static void disable_counter(struct perf_data *pd, int counter)
{
	int ret;

	if (unlikely(counter < 0 || counter >= MAX_COUNTERS))
		panic("bug! invalid counter value!\n");
	if (pd->fds[counter] == FDS_INVALID)
		return;

	ret = ioctl(pd->fds[counter], PERF_EVENT_IOC_DISABLE);
	if (ret)
		panic("error disabling perf counter!\n");
}

static void disable_all_counter(struct perf_data *pd)
{
	int ret, i;

	/* XXX: Only group leader? */
	for (i = 0; i < MAX_COUNTERS; i++) {
		disable_counter(pd, i);
	}
}

static void cleanup(struct perf_data *pd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(default_attrs); i++)
		if (pd->fds[i] >= 0)
			close(pd->fds[i]);
	xfree(pd->attrs);
	xfree(pd);
}

static void list_counter(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(whole_map); i++)
		printf("%s\n", whole_map[i].name);

	die();
}

static enum tracepoint lookup_counter(char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(whole_map); i++) 
		if (!strncmp(whole_map[i].name, name, sizeof(whole_map[i].name) - 1))
			return whole_map[i].tracepoint;
	return INTERNAL_INVALID_TP;
}

static void print_whole_result(struct perf_data *pd)
{
	uint64_t tmp1, tmp2;

	printf("Software counters:\n");
	printf("  CPU clock ticks %" PRIu64 "\n", read_counter(pd, COUNT_SW_CPU_CLOCK));
	printf("  task clock ticks %" PRIu64 "\n", read_counter(pd, COUNT_SW_TASK_CLOCK));
	printf("  CPU context switches %" PRIu64 "\n", read_counter(pd, COUNT_SW_CONTEXT_SWITCHES));
	printf("  CPU migrations %" PRIu64 "\n", read_counter(pd, COUNT_SW_CPU_MIGRATIONS));
	printf("  pagefaults/minor/major %" PRIu64 "/%" PRIu64 "/%" PRIu64 "\n",
	       read_counter(pd, COUNT_SW_PAGE_FAULTS),
	       read_counter(pd, COUNT_SW_PAGE_FAULTS_MIN),
	       read_counter(pd, COUNT_SW_PAGE_FAULTS_MAJ));
	printf("Hardware counters:\n");
	printf("  CPU cycles %" PRIu64 "\n", read_counter(pd, COUNT_HW_CPU_CYCLES));
	printf("  instructions %" PRIu64 "\n", read_counter(pd, COUNT_HW_INSTRUCTIONS));
	tmp1 = read_counter(pd, COUNT_HW_CACHE_REFERENCES);
	tmp2 = read_counter(pd, COUNT_HW_CACHE_MISSES);
	printf("  cache references %" PRIu64 "\n", tmp1);
	printf("  cache misses (rate) %" PRIu64 " (%.4lf %%)\n", tmp2, (1.0 * tmp2 / tmp1) * 100.0);
	tmp1 = read_counter(pd, COUNT_HW_BRANCH_INSTRUCTIONS);
	tmp2 = read_counter(pd, COUNT_HW_BRANCH_MISSES);
	printf("  branch instructions %" PRIu64 "\n", tmp1);
	printf("  branch misses (rate) %" PRIu64 " (%.4lf %%)\n", tmp2, (1.0 * tmp2 / tmp1) * 100.0);
	printf("  bus cycles %" PRIu64 "\n", read_counter(pd, COUNT_HW_BUS_CYCLES));
	printf("L1D, data cache:\n");
	printf("  loads %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_L1D_LOADS));
	printf("  load misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_L1D_LOADS_MISSES));
	printf("  stores %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_L1D_STORES));
	printf("  store misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_L1D_STORES_MISSES));
	printf("  prefetches %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_L1D_PREFETCHES));
	printf("L1I, instruction cache:\n");
	printf("  loads %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_L1I_LOADS));
	printf("  load misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_L1I_LOADS_MISSES));
	printf("LL, last level cache:\n");
	printf("  loads %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_LL_LOADS));
	printf("  load misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_LL_LOADS_MISSES));
	printf("  stores %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_LL_STORES));
	printf("  store misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_LL_STORES_MISSES));
	printf("DTLB, data translation lookaside buffer:\n");
	printf("  loads %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_DTLB_LOADS));
	printf("  load misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_DTLB_LOADS_MISSES));
	printf("  stores %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_DTLB_STORES));
	printf("  store misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_DTLB_STORES_MISSES));
	printf("ILLB, instruction translation lookaside buffer:\n");
	printf("  loads %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_ITLB_LOADS));
	printf("  load misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_ITLB_LOADS_MISSES));
	printf("BPU, branch prediction unit:\n");
	printf("  loads %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_BPU_LOADS));
	printf("  load misses %" PRIu64 "\n", read_counter(pd, COUNT_HW_CACHE_BPU_LOADS_MISSES));
	printf("Wall-clock time elapsed:\n");
	printf("  usec %" PRIu64 "\n", read_counter(pd, INTERNAL_SW_WALL_TIME));
}

int main(int argc, char **argv)
{
	int status, c, opt_index, mode, pt, cpu, excl, ret;
	unsigned long cpus;
	pid_t pid = -1;
	struct perf_data *pd;
	enum tracepoint tp;

	if (argc == 1)
		usage();

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	cpu = -1;
	mode = excl = pt = 0;
	tp = INTERNAL_INVALID_TP;

	while ((c = getopt_long(argc, argv, short_options, long_options,
				&opt_index)) != EOF) {
		switch (c) {
		case 'h':
			usage();
			break;
		case 'v':
			version();
			break;
		case 'p':
			pid = atoi(optarg);
			if (pid < 0)
				panic("bad pid! either 0 for all procs "
				      "or x > 0!\n");
			if (pid == 0)
				pid = -1;
			else
				pt = 1;
			whine("not yet working correctly!\n");
			break;
		case 'c':
			cpu = atoi(optarg);
			if (cpu < 0 || cpu >= cpus)
				panic("bad cpuid! needs to be 0 <= x < "
				      "%lu!\n", cpus);
			break;
		case 'e':
			excl = 1;
			break;
		case 'k':
			mode |= MODE_KERNEL;
			break;
		case 'u':
			mode |= MODE_USER;
			break;
		case 'y':
			mode |= MODE_HYPER;
			break;
		case 'i':
			mode |= MODE_IDLE;
			break;
		case 'l':
			list_counter();
			break;
		case 'x':
			tp = lookup_counter(optarg);
			printf("found: %d\n", tp);
			break;
		default:
			usage();
			break;
		}
	}

	if (pt && pid == -1 && cpu == -1)
		panic("either all procs on a single core or all cpus on a "
		      "single proc, but not both!\n");

	if (mode == 0)
		mode = MODE_KERNEL | MODE_USER | MODE_HYPER;

	if (!pt)
		pid = fork();
	else {
		register_signal(SIGCHLD, reaper);
		ret = ptrace(PT_ATTACH, pid, (char *) 1, 0);
		if (ret < 0) {
			panic("cannot attach to process!\n");
			perror("");
		}
		fprintf(stderr, "Process %u attached - interrupt to quit\n",
			pid);
	}

	pd = initialize(pid, cpu, mode, excl);
	if (tp == INTERNAL_INVALID_TP)
		enable_all_counter(pd);
	else
		enable_counter(pd, tp);

	if (!pt && !pid) {
		execvp(argv[optind], &argv[optind]);
		die();
	}
	register_signal(SIGINT, intr);
	wait(&status);
	if (tp == INTERNAL_INVALID_TP)
		disable_all_counter(pd);
	else
		disable_counter(pd, tp);

	if (pt) {
		ret = ptrace(PT_DETACH, pid, (char *) 1, SIGCONT);
		if (ret < 0) {
			panic("cannot detach from process!\n");
			perror("");
		}
		fprintf(stderr, "Process %u detached\n", pid);
	}

	if (cpu == -1)
		printf("CPU: all, PID: %d\n", pid);
	else
		printf("CPU: %d, PID: %d\n", cpu, pid);
	printf("Kernel: %s, User: %s, Hypervisor: %s\n",
	       (mode & MODE_KERNEL) == MODE_KERNEL ? "on" : "off", 
	       (mode & MODE_USER) == MODE_USER ? "on" : "off", 
	       (mode & MODE_HYPER) == MODE_HYPER ? "on" : "off");

	if (tp == INTERNAL_INVALID_TP)
		print_whole_result(pd);
	else
		printf("%" PRIu64 " in %" PRIu64 " usec\n",
		       read_counter(pd, tp),
		       read_counter(pd, INTERNAL_SW_WALL_TIME));
	cleanup(pd);

	return 0;
}
