/*
 * IPv4 Link-Local Address Selection
 *
 * This file implements the main entry-point of n-ipv4ll. This includes the
 * entire context object and event handling. All real protocol handling is
 * outsourced to `n-acd`.
 */

/**
 * DOC: IPv4 Link-Local Address Selection
 *
 * The `n-ipv4ll` project implements IPv4 Link-Local Address Selection as
 * specified in RFC-3927. It defines a way to acquire IPv4 addresses on a local
 * link without configuration required, nor any network management utilities
 * running. It uses a private subnet which is never routed and only allows link
 * local communication. When a device connects to a network, it will probe a
 * random sequence of addresses for conflicts. The first available address is
 * then used and maintained until further conflicts are noticed, in which case
 * the address might change again.
 *
 * Note that this project only implements the networking protocol. It never
 * queries or modifies network interfaces. It completely relies on the API user
 * to react to notifications and update network interfaces respectively.
 * Furthermore, an event-queue is used for every object. The event queue allows
 * asynchronous reactions to events from the triggering object. The events are
 * carefully assigned to never require synchronous handling. Hence, the API
 * should be straightforward to remote through IPC (or even networking).
 */

#include <assert.h>
#include <c-list.h>
#include <errno.h>
#include <n-acd.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "n-ipv4ll.h"
#include "n-ipv4ll-private.h"

/**
 * n_ipv4ll_config_new() - create configuration object
 * @configp:                    output argument for new configuration object
 *
 * This creates a new configuration object and returns it in @configp to the
 * caller. Upon function return, the caller fully owns the object.
 *
 * Configuration objects are used to collect parameters for other functions. No
 * input validation is done by the configuration object, but the consumer of
 * the configuration is required to validate the parameters.
 *
 * Return: 0 on success, negative error code on failure.
 */
_public_ int n_ipv4ll_config_new(NIpv4llConfig **configp) {
        _cleanup_(n_ipv4ll_config_freep) NIpv4llConfig *config = NULL;

        config = malloc(sizeof(*config));
        if (!config)
                return -ENOMEM;

        *config = (NIpv4llConfig)N_IPV4LL_CONFIG_NULL(*config);

        *configp = config;
        config = NULL;
        return 0;
}

/**
 * n_ipv4ll_config_free() - destroy configuration object
 * @config:                     configuration to operate on, or NULL
 *
 * This destroys the configuration object provided as @config. If @config is
 * NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
_public_ NIpv4llConfig *n_ipv4ll_config_free(NIpv4llConfig *config) {
        if (!config)
                return NULL;

        free(config);

        return NULL;
}

/**
 * n_ipv4ll_config_set_ifindex() - set ifindex property
 * @config:                     configuration to operate on
 * @ifindex:                    ifindex property
 *
 * This sets the interface index property of the configuration. This property
 * selects the network interface to use. Any value smaller than, or equal to, 0
 * specifies no interface.
 *
 * It is the caller's resposnibility to provide a valid interface as well as
 * guarantee the interface is fully functional.
 *
 * Default value is 0.
 */
_public_ void n_ipv4ll_config_set_ifindex(NIpv4llConfig *config, int ifindex) {
        config->ifindex = ifindex;
}

/**
 * n_ipv4ll_config_set_transport() - set transport property
 * @config:                     configuration to operate on
 * @transport:                  transport property
 *
 * This sets the transport property of the configuration. The transport is
 * specified as one of the `N_IPV4LL_TRANSPORT_*` selectors. The transport
 * specifies the underlying hardware type that the ipv4ll engine will run on.
 *
 * Default is no transport selection.
 */
_public_ void n_ipv4ll_config_set_transport(NIpv4llConfig *config, unsigned int transport) {
        config->transport = transport;
}

/**
 * n_ipv4ll_config_set_mac() - set mac property
 * @config:                     configuration to operate on
 * @mac:                        mac property
 * @n_mac:                      length of @mac
 *
 * This sets the mac property of the configuration. It specifies the local
 * hardware address to use for communication. It is the caller's responsibility
 * to provide a valid address that is ready to be used.
 *
 * Default is a zero-length address.
 */
_public_ void n_ipv4ll_config_set_mac(NIpv4llConfig *config, const uint8_t *mac, size_t n_mac) {
        /*
         * We truncate the address if it exceeds the maximum we support. This
         * does not lose information, since we retain the original length
         * value. It is up to the consumer of this configuration to validate
         * whether the address was truncated or not. Since all transports we
         * support have fixed-length addresses, a valid address will never be
         * truncated.
         */
        config->n_mac = n_mac;
        memcpy(config->mac, mac, n_mac > ETH_ALEN ? ETH_ALEN : n_mac);
}

/**
 * n_ipv4ll_config_set_enumeration() - set enumeration property
 * @config:                     configuration to operate on
 * @enumeration:                enumeration property
 *
 * This sets the enumeration property of the configuration. This property
 * specifies the start value of the address selector, and as such defines the
 * order in which addresses are probed.
 *
 * The enumeration selector is a simple 64bit number that is used to seed the
 * random number generator of the ipv4ll address selector. If the same
 * enumeration is used for two ipv4ll engines, they will try the same addresses
 * in the same order. It is thus important to use different enumerations for
 * every device, otherwise the address selection might never settle.
 *
 * Default is no selected enumeration.
 */
_public_ void n_ipv4ll_config_set_enumeration(NIpv4llConfig *config, uint64_t enumeration) {
        config->enumeration = enumeration;
        config->enumeration_set = true;
}

/**
 * n_ipv4ll_config_set_timeout() - set timeout property
 * @config:                     configuration to operate on
 * @timeout:                    timeout property
 *
 * This sets the timeout property of the configuration. This specifies the
 * total time available to probe for an individual address.
 *
 * See n_acd_probe_config_set_timeout() for details on this property.
 *
 * Default is the same as specified by `n-acd` (usually the default specified
 * in the ACD specification RFC-5227, which is roughly 9s).
 */
_public_ void n_ipv4ll_config_set_timeout(NIpv4llConfig *config, uint64_t timeout) {
        config->timeout_msecs = timeout;
}

/**
 * n_ipv4ll_config_set_requested_ip() - set requested-ip property
 * @config:                     configuration to operate on
 * @ip:                         requested-ip property
 *
 * This sets the requested-ip property. It specifies the initial address to
 * request. If this address cannot be claimed, the next address to try is
 * picked through the enumeration property.
 *
 * Default is no address (i.e., `INADDR_ANY`).
 */
_public_ void n_ipv4ll_config_set_requested_ip(NIpv4llConfig *config, struct in_addr ip) {
        config->requested_ip = ip;
}

static int n_ipv4ll_event_node_new(NIpv4llEventNode **nodep) {
        NIpv4llEventNode *node;

        node = malloc(sizeof(*node));
        if (!node)
                return -ENOMEM;

        *node = (NIpv4llEventNode)N_IPV4LL_EVENT_NODE_NULL(*node);

        *nodep = node;
        return 0;
}

static NIpv4llEventNode *n_ipv4ll_event_node_free(NIpv4llEventNode *node) {
        if (!node)
                return NULL;

        c_list_unlink(&node->ipv4ll_link);
        free(node);

        return NULL;
}

static void n_ipv4ll_select_ip(NIpv4ll *ll, struct in_addr *ip) {
        long int result;
        uint16_t offset;

        (void)mrand48_r(&ll->enumeration_state, &result);

        /*
         * If mrand48_r had produced a perfect random distribution
         * this would be redundant, but let's assume that it does
         * not and take advantage of all the entropy we get.
         */
        offset = result ^ (result >> 16);

        /*
         * The first and the last 256 addresses in the subnet are
         * reserved. Shrink the range by 512 addresses, then shift
         * it up by 256. Note that this does not preserve a uniform
         * distribution, however the distortion will be miniscule
         * (the 512 invalid addresses will not be redistributed
         * perfectly, but they are anyway such a small proportion
         * of the range that it should not be important.
         *
         * We could have skipped the invalid addresses in a loop,
         * but this way the runtime is fixed. In particular, we
         * don't have to worry about mrand48_r somehow ending up
         * producing an infinite stream of invalid addresses for
         * a given seed, which would have caused a busy-loop.
         */
        offset = (offset % ((1 << 16) - (1 << 9))) + (1 << 8);

        ip->s_addr = htobe32(IPV4LL_NETWORK | offset);
}

/**
 * n_ipv4ll_new() - create a new IPv4LL context
 * @ipv4llp:                    output argument for context
 * @config:                     configuration parameters
 *
 * Create a new IPv4LL context and return it in @ipv4llp. The configuration in
 * @config is used to set the context up. The required configuration is copied
 * into the context, so @config is no longer needed upon function return.
 *
 * Context creation will immediately start the address selection with the
 * specified parameters. The caller is required to poll on the context fd
 * returned by n_ipv4ll_get_fd() and dispatch it on events via
 * n_ipv4ll_dispatch().
 *
 * Return: 0 on success, N_ACD_E_INVALID_ARGUMENT if the configuration is not
 *         valid, negative error code on failure.
 */
_public_ int n_ipv4ll_new(NIpv4ll **ipv4llp, NIpv4llConfig *config) {
        _cleanup_(n_ipv4ll_freep) NIpv4ll *ipv4ll = NULL;
        _cleanup_(n_acd_config_freep) NAcdConfig *acd_config = NULL;
        int r;

        if (config->ifindex <= 0 ||
            config->transport != N_IPV4LL_TRANSPORT_ETHERNET ||
            config->n_mac != ETH_ALEN ||
            !memcmp(config->mac, (uint8_t[ETH_ALEN]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, ETH_ALEN) ||
            !config->enumeration_set)
                return N_ACD_E_INVALID_ARGUMENT;

        if (config->requested_ip.s_addr != INADDR_ANY) {
                if (be32toh(config->requested_ip.s_addr) < (IPV4LL_NETWORK | 0x0100) ||
                    be32toh(config->requested_ip.s_addr) > (IPV4LL_NETWORK | 0xfeff))
                        return N_IPV4LL_E_INVALID_ARGUMENT;
        }

        ipv4ll = malloc(sizeof(*ipv4ll));
        if (!ipv4ll)
                return -ENOMEM;

        *ipv4ll = (NIpv4ll)N_IPV4LL_NULL(*ipv4ll);

        (void) seed48_r((unsigned short int*) &config->enumeration, &ipv4ll->enumeration_state);

        if (config->requested_ip.s_addr != INADDR_ANY)
                ipv4ll->ip = config->requested_ip;
        else
                n_ipv4ll_select_ip(ipv4ll, &ipv4ll->ip);

        r = n_acd_config_new(&acd_config);
        if (r) {
                if (r > 0)
                        r = -ENOTRECOVERABLE;
                return r;
        }

        n_acd_config_set_ifindex(acd_config, config->ifindex);
        n_acd_config_set_transport(acd_config, N_ACD_TRANSPORT_ETHERNET);
        n_acd_config_set_mac(acd_config, config->mac, ETH_ALEN);

        r = n_acd_new(&ipv4ll->acd, acd_config);
        if (r) {
                if (r > 0)
                        r = -ENOTRECOVERABLE;
                return r;
        }

        r = n_acd_probe_config_new(&ipv4ll->config);
        if (r) {
                if (r > 0)
                        r = -ENOTRECOVERABLE;
                return r;
        }

        n_acd_probe_config_set_timeout(ipv4ll->config, config->timeout_msecs);
        n_acd_probe_config_set_ip(ipv4ll->config, ipv4ll->ip);

        r = n_acd_probe(ipv4ll->acd, &ipv4ll->probe, ipv4ll->config);
        if (r) {
                if (r > 0)
                        r = -ENOTRECOVERABLE;
                return r;
        }

        *ipv4llp = ipv4ll;
        ipv4ll = NULL;
        return 0;
}

/**
 * n_ipv4ll_free() - free context
 * @ipv4ll:                     context to operat on, or NULL
 *
 * Frees all resources held by the context. This may be called at any time,
 * but doing so invalidates all data owned by the context.
 *
 * If @ipv4ll is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
_public_ NIpv4ll *n_ipv4ll_free(NIpv4ll *ipv4ll) {
        NIpv4llEventNode *node, *t_node;

        if (!ipv4ll)
                return NULL;

        c_list_for_each_entry_safe(node, t_node, &ipv4ll->event_list, ipv4ll_link)
                n_ipv4ll_event_node_free(node);

        n_acd_probe_config_free(ipv4ll->config);
        n_acd_probe_free(ipv4ll->probe);
        n_acd_unref(ipv4ll->acd);

        free(ipv4ll);

        return NULL;
}

/**
 * n_ipv4ll_get_fd() - get pollable file descriptor
 * @ipv4ll:                     context to operate on
 * @fdp:                        output argument for file descriptor
 *
 * Returns a file descriptor in @fdp. This file descriptor can be polled by
 * the caller to indicate when the IPv4LL context can be dispatched. The
 * internal implementation of this file-descriptor is not part of the API. That
 * is, the file-descriptor is internal to the context and must not be used for
 * anything but polling.
 *
 * The caller is supposed to poll the FD for readability and call into
 * n_ipv4ll_dispatch() whenever it shows activity.
 *
 * The file-descriptor is fixed to the lifetime of @ipv4ll and will not change.
 * The caller is free to cache the value as long as @ipv4ll is valid.
 *
 * Currently, the file-descriptor is an epoll-fd.
 */
_public_ void n_ipv4ll_get_fd(NIpv4ll *ipv4ll, int *fdp) {
        n_acd_get_fd(ipv4ll->acd, fdp);
}

static int n_ipv4ll_raise(NIpv4ll *ipv4ll, NIpv4llEventNode **nodep, unsigned int event) {
        NIpv4llEventNode *node;
        int r;

        r = n_ipv4ll_event_node_new(&node);
        if (r < 0)
                return r;

        node->event.event = event;
        c_list_link_tail(&ipv4ll->event_list, &node->ipv4ll_link);

        if (nodep)
                *nodep = node;
        return 0;
}

static int n_ipv4ll_handle_acd_event(NIpv4ll *ipv4ll, NAcdEvent *event) {
        NIpv4llEventNode *node;
        int r;

        switch (event->event) {
        case N_ACD_EVENT_READY:
                r = n_ipv4ll_raise(ipv4ll, &node, N_IPV4LL_EVENT_READY);
                if (r < 0)
                        return r;

                node->event.ready.ip = ipv4ll->ip;

                break;

        case N_ACD_EVENT_DEFENDED:
                r = n_ipv4ll_raise(ipv4ll, &node, N_IPV4LL_EVENT_DEFENDED);
                if (r < 0)
                        return r;

                node->event.defended.sender = node->sender;
                node->event.defended.n_sender = ETH_ALEN;
                memcpy(node->sender, event->defended.sender, ETH_ALEN);

                break;

        case N_ACD_EVENT_CONFLICT:
                r = n_ipv4ll_raise(ipv4ll, &node, N_IPV4LL_EVENT_CONFLICT);
                if (r < 0)
                        return r;

                node->event.conflict.sender = node->sender;
                node->event.conflict.n_sender = ETH_ALEN;
                memcpy(node->sender, event->conflict.sender, ETH_ALEN);

                /* fall-through */
        case N_ACD_EVENT_USED:
                ipv4ll->probe = n_acd_probe_free(ipv4ll->probe);
                n_ipv4ll_select_ip(ipv4ll, &ipv4ll->ip);
                n_acd_probe_config_set_ip(ipv4ll->config, ipv4ll->ip);

                r = n_acd_probe(ipv4ll->acd, &ipv4ll->probe, ipv4ll->config);
                if (r) {
                        if (r > 0)
                                r = -ENOTRECOVERABLE;
                        return r;
                }

                break;
        case N_ACD_EVENT_DOWN:
                r = n_ipv4ll_raise(ipv4ll, NULL, N_IPV4LL_EVENT_DOWN);
                if (r < 0)
                        return r;

                break;
        }

        return 0;
}

/**
 * n_ipv4ll_dispatch() - dispatch IPv4LL context
 * @ipv4ll:                     context to operate on
 *
 * This dispatches all internal operations of the given context. It will parse
 * incoming packets, send out packets, and advance the state-machine.
 *
 * Any events to the caller are queued on the context. Any interaction with the
 * API user is performed through the event-queue.
 *
 * The caller is required to drain the event queue after calling this
 * dispatcher. See n_ipv4ll_pop_event().
 *
 * Return: 0 on success, N_IPV4LL_E_PREEPMTED on preemption, negative error
 *         code on failure.
 */
_public_ int n_ipv4ll_dispatch(NIpv4ll *ipv4ll) {
        bool preempted = false;
        int r;

        r = n_acd_dispatch(ipv4ll->acd);
        if (r == N_ACD_E_PREEMPTED) {
                preempted = true;
        } else if (r) {
                if (r > 0)
                        r = -ENOTRECOVERABLE;
                return r;
        }

        for (;;) {
                NAcdEvent *event;

                r = n_acd_pop_event(ipv4ll->acd, &event);
                if (r) {
                        if (r > 0)
                                r = -ENOTRECOVERABLE;
                        return r;
                }

                if (!event)
                        break;

                r = n_ipv4ll_handle_acd_event(ipv4ll, event);
                if (r < 0)
                        return r;
        }

        return preempted ? N_IPV4LL_E_PREEMPTED : 0;
}

/**
 * n_ipv4ll_pop_event() - get the next pending event
 * @ipv4ll:                     context to operate on
 * @eventp:                     output argument for the event
 *
 * Returns a pointer to the next pending event. The event is still owned by
 * the context, and is only valid until the next call to n_ipv4ll_pop_event()
 * or until the context is freed.
 *
 * Once the event queue is drained, @eventp is set to NULL and 0 is returned.
 *
 * The possible events are:
 *  * N_IPV4LL_EVENT_READY:    The configured IP address was probed
 *                             successfully and is ready to be used. Once
 *                             configured on the interface, the caller must
 *                             call n_ipv4ll_announce() to announce and start
 *                             defending the address. No further events may
 *                             be received before n_ipv4ll_announce() has been
 *                             called.
 *  * N_IPV4LL_EVENT_DEFENDED: A conflict was detected for the announced IP
 *                             address, and the engine tried to defend it.
 *                             This is purely informational, and no action
 *                             is required from the caller.
 *  * N_IPV4LL_EVENT_CONFLICT: A conflict was detected for the announced IP
 *                             address, and the engine failed to defend it. The
 *                             caller must immediately cease using the address.
 *                             The engine will automatically continue probing
 *                             the next address.
 *  * N_IPV4LL_EVENT_DOWN:     A network error was detected. This is purely
 *                             informational and has no effect on the state
 *                             machine. It is the caller's responsibility to
 *                             detect disfunctional networks and cease
 *                             operation.
 *
 * Return: 0 on success, negative error code on failure.
 */
_public_ int n_ipv4ll_pop_event(NIpv4ll *ipv4ll, NIpv4llEvent **eventp) {
        NIpv4llEventNode *node, *t_node;

        c_list_for_each_entry_safe(node, t_node, &ipv4ll->event_list, ipv4ll_link) {
                if (node->is_public) {
                        n_ipv4ll_event_node_free(node);
                        continue;
                }

                node->is_public = true;
                *eventp = &node->event;
                return 0;
        }

        *eventp = NULL;
        return 0;
}

/**
 * n_ipv4ll_announce() - announce the configured IP address
 * @ipv4ll:                     context to operate on
 *
 * Announce the IP address on the local link, and start defending it.
 *
 * This must be called in response to an N_IPV4LL_EVENT_READY event,
 * and only once the address has been configured on the given interface.
 *
 * Return: 0 on success, negative error code on failure.
 */
_public_ int n_ipv4ll_announce(NIpv4ll *ipv4ll) {
        int r;

        r = n_acd_probe_announce(ipv4ll->probe, N_ACD_DEFEND_ONCE);
        if (r) {
                if (r > 0)
                        r = -ENOTRECOVERABLE;
                return r;
        }

        return 0;
}
