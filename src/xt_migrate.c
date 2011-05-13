/*
 * Lightweight Autonomic Network Architecture
 *
 * Migration function for tasks. Tasks will be rescheduled with another
 * CPU affinity, so that PPEs are the only users on a CPU. Usefull for
 * Appliances like Routers.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>


