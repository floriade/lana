/*
 * Lightweight Autonomic Network Architecture
 *
 * Ingress and egress flow scheduler. Flows that traverse the network stack,
 * e.g. ranging from PHY to the socket handler, are kept CPU-affine for the
 * communication. This scheduler classifies the packet and enqueues it into
 * the specific PPE.
 *
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

