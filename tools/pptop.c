/*
 * pptop - Linux performance counter subsystem uspace tracing
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
 * pptop (aka process perf top) has been written by
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 *
 * Needs Linux kernel >= 2.6.32. For more detailed information have a look at 
 * tools/perf/design.txt and http://lkml.org/lkml/2009/6/6/149.
 *
 * Compile: gcc cputrace.c -o cputrace -O2 -lrt
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
	__u64 disabled:1,       /* off by default */
	      inherit:1,        /* children inherit it */
	      pinned:1,         /* must always be on PMU */
	      exclusive:1,      /* only group on PMU */
	      exclude_user:1,   /* don't count user */
	      exclude_kernel:1, /* ditto kernel */
	      exclude_hv:1,     /* ditto hypervisor */
	      exclude_idle:1,   /* don't count when idle */
	      mmap:1,           /* include mmap data */
	      comm:1,           /* include comm data */
	      freq:1,           /* use freq, not period */
	      inherit_stat:1,   /* per task counts */
	      enable_on_exec:1, /* next exec enables */
	      task:1,           /* trace fork/exit */
	      watermark:1,      /* wakeup_watermark */
	      /*
	       * precise_ip:
	       * 0 - SAMPLE_IP can have arbitrary skid
	       * 1 - SAMPLE_IP must have constant skid
	       * 2 - SAMPLE_IP requested to have 0 skid
	       * 3 - SAMPLE_IP must have 0 skid
	       * See also PERF_RECORD_MISC_EXACT_IP
	       */
	      precise_ip:2,      /* skid constraint */
	      __reserved_1:47;
	union {
		__u32 wakeup_events;    /* wakeup every n events */
		__u32 wakeup_watermark; /* bytes before wakeup */
	};
	__u32 bp_type;
	__u64 bp_addr;
	__u64 bp_len;
};

/*
 * Ioctls that can be done on a perf event fd:
 */
#define PERF_EVENT_IOC_ENABLE _IO ('$', 0)
#define PERF_EVENT_IOC_DISABLE _IO ('$', 1)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define MAX_COUNTERS 32

#define FDS_INVALID  -1
#define GRP_INVALID  -1

#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef bug
# define bug() __builtin_trap()
#endif

#define PROGNAME "cputrace"
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
	INTERNAL_SW_WALL_TIME = 33
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

struct perf_data {
	pid_t pid;
	int cpu;
	int group;
	int fds[MAX_COUNTERS];
	struct perf_event_attr *attrs;
	unsigned long long wall_start;
	FILE *log;
};

struct perf_stats {
	double n, mean, M2;
};

static inline unsigned long long rdclock(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
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

static void *xmalloc(size_t size)
{
	void *ptr;

	if (unlikely(size == 0))
		panic("xmalloc: zero size\n");

	ptr = malloc(size);
	if (unlikely(ptr == NULL))
		panic("xmalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) size);

	return ptr;
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

static void *xmalloc_aligned(size_t size, size_t alignment)
{
	int ret;
	void *ptr;

	if (unlikely(size == 0))
		panic("xmalloc_aligned: zero size\n");

	ret = posix_memalign(&ptr, alignment, size);
	if (unlikely(ret != 0))
		panic("xmalloc_aligned: out of memory (allocating %lu bytes)\n",
		      (u_long) size);

	return ptr;
}

static void xfree(void *ptr)
{
	if (unlikely(ptr == NULL))
		panic("xfree: NULL pointer given as argument\n");
	free(ptr);
}

static void update_stats(struct perf_stats *stats, uint64_t val)
{
	double delta;

	stats->n++;
	delta = val - stats->mean;
	stats->mean += delta / stats->n;
	stats->M2 += delta * (val - stats->mean);
}

static double avg_stats(struct perf_stats *stats)
{
	return stats->mean;
}

static inline int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid,
				      int cpu, int group_fd, unsigned long flags)
{
	attr->size = sizeof(*attr);
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static inline pid_t gettid()
{
	return syscall(SYS_gettid);
}

static struct perf_data *perf_initialize(pid_t pid, int cpu)
{
	int fd, i, ret;
	char logname[256];
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

	memset(logname, 0, sizeof(logname));
	ret = snprintf(logname, sizeof(logname), "/tmp/cputrace.%d", pid);
	if (unlikely(ret < 0))
		panic("snprintf screwed up!\n");

	fd = open(logname, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR |
			   S_IRGRP | S_IROTH);
	if (unlikely(fd < 0))
		panic("cannot open log file %s!\n", logname);
	pd->log = fdopen(fd, "a");
	if (unlikely(!pd->log))
		panic("fdopen cannot map fd!\n");

	for (i = 0; i < ARRAY_SIZE(default_attrs); i++) {
		attr = &attrs[i];

		attr->inherit = 1; /* default */
		attr->disabled = 1;
		attr->enable_on_exec = 0;

		pd->fds[i] = sys_perf_event_open(attr, pid, cpu, GRP_INVALID, 0);
		if (unlikely(pd->fds[i] < 0))
			panic("sys_perf_event_open failed!\n");
	}

	pd->wall_start = rdclock();

	return pd;
}

static void perf_finalize(struct perf_data *pd, void *id)
{
	int i, ret, *fds;
	uint64_t count[3];
	struct perf_stats event_stats[ARRAY_SIZE(default_attrs)];
	struct perf_stats walltime_nsecs_stats;

	for (fds = pd->fds, i = 0; i < ARRAY_SIZE(default_attrs); i++) {
		if (fds[i] < 0)
			panic("caught bad file descriptor!\n");

		ret = read(fds[i], count, sizeof(uint64_t));
		if (unlikely(ret != sizeof(uint64_t)))
			panic("perf_counter read error!\n");

		update_stats(&event_stats[i], count[0]);

		close(fds[i]);
		fds[i] = FDS_INVALID;

		fprintf(pd->log, "stats [%p, %d]: %14.0f\n", id, i, avg_stats(&event_stats[i]));
	}

	update_stats(&walltime_nsecs_stats, rdclock() - pd->wall_start);

	fprintf(pd->log, "stats [%p, %d]: %14.9f\n", id, i, avg_stats(&walltime_nsecs_stats) / 1e9);
	fclose(pd->log);

	xfree(pd->attrs);
	xfree(pd);
}

static uint64_t perf_read_counter(struct perf_data *pd, int counter)
{
	int ret;
	uint64_t value;

	if (unlikely(counter < 0 || counter > MAX_COUNTERS))
		panic("bug! invalid counter value!\n");
	if (counter == MAX_COUNTERS)
		return (uint64_t) (rdclock() - pd->wall_start);

	ret = read(pd->fds[counter], &value, sizeof(uint64_t));
	if (unlikely(ret != sizeof(uint64_t)))
		panic("perf_counter read error!\n");

	return value;
}

static void perf_enable_counter(struct perf_data *pd, int counter)
{
	int ret;

	if (unlikely(counter < 0 || counter >= MAX_COUNTERS))
		panic("bug! invalid counter value!\n");
	if (pd->fds[counter] == FDS_INVALID) {
		pd->fds[counter] = sys_perf_event_open(&pd->attrs[counter], pd->pid,
						       pd->cpu, pd->group, 0);
		if (unlikely(pd->fds[counter] < 0))
			panic("sys_perf_event_open failed!\n");
	}

	ret = ioctl(pd->fds[counter], PERF_EVENT_IOC_ENABLE);
	if (ret)
		panic("error enabling perf counter!\n");
}

static void perf_disable_counter(struct perf_data *pd, int counter)
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

static void perf_cleanup(struct perf_data *pd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(default_attrs); i++)
		if (pd->fds[i] >= 0)
			close(pd->fds[i]);
	fclose(pd->log);

	xfree(pd->attrs);
	xfree(pd);
}

static FILE *perf_get_logger(struct perf_data *pd)
{
	return pd->log;
}

static void usage(void)
{
	printf("\n%s %s\n", PROGNAME, VERSNAME);
	printf("Usage: cputrace <cmd> || cputrace [options]\n");
	printf("Options:\n");
	printf("  -p|--pid <pid>         Attach to running process\n");
	printf("  -e|--event <e>         Specify event (default: COUNT_HW_CACHE_MISSES)\n");
	printf("  -l|--list              List available events\n");
	printf("  -t|--interval <time>   Refresh time in seconds as float (default 1.0)\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
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

int main(int argc, char **argv)
{
	int status;
	pid_t pid;
	uint64_t counter;
	struct perf_data *pd;

	if (argc == 1)
		usage();

	pid = fork();
	pd = perf_initialize(pid, -1);
	perf_enable_counter(pd, COUNT_HW_CACHE_MISSES);

	if (!pid)
		execvp(argv[1], &argv[1]);
	else {
		wait(&status);
		counter = perf_read_counter(pd, COUNT_HW_CACHE_MISSES);

		perf_disable_counter(pd, COUNT_HW_CACHE_MISSES);
		fprintf(stdout, "counter read: %" PRIu64 "\n", counter);
	}

	perf_finalize(pd, 0);
	return 0;
}
