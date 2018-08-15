/*
 * IPv4 Link-Local Address Selection
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
 * XXX
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
 * XXX
 */
_public_ NIpv4llConfig *n_ipv4ll_config_free(NIpv4llConfig *config) {
        if (!config)
                return NULL;

        free(config);

        return NULL;
}

/**
 * XXX
 */
_public_ void n_ipv4ll_config_set_ifindex(NIpv4llConfig *config, int ifindex) {
        config->ifindex = ifindex;
}

/**
 * XXX
 */
_public_ void n_ipv4ll_config_set_transport(NIpv4llConfig *config, unsigned int transport) {
        config->transport = transport;
}

/**
 * XXX
 */
_public_ void n_ipv4ll_config_set_mac(NIpv4llConfig *config, const uint8_t *mac, size_t n_mac) {
        config->n_mac = n_mac;
        memcpy(config->mac, mac, n_mac > ETH_ALEN ? ETH_ALEN : n_mac);
}

/**
 * XXX
 */
_public_ void n_ipv4ll_config_set_enumeration(NIpv4llConfig *config, uint64_t enumeration) {
        config->enumeration = enumeration;
        config->enumeration_set = true;
}

/**
 * XXX
 */
_public_ void n_ipv4ll_config_set_timeout(NIpv4llConfig *config, uint64_t timeout) {
        config->timeout_msecs = timeout;
}

/**
 * XXX
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
         * of the range that that should not be important.
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
 * @ipv4llp:        output argument for context
 * @config:         configuration parameters
 *
 * Create a new IPv4LL context and return it in @ipv4llp.
 *
 * Return: 0 on success, or a non-zero error code on failure.
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
 * n_ipv4ll_free() - free an IPv4LL context
 * @ll:         IPv4LL context
 *
 * Frees all resources held by the context. This may be called at any time,
 * but doing so invalidates all data owned by the context.
 *
 * Return: NULL.
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
 * @ll:         IPv4LL context
 * @fdp:        output argument for file descriptor
 *
 * Returns a file descriptor in @fdp. This file descriptor can be polled by
 * the caller to indicate when the IPv4LL context can be dispatched.
 */
_public_ void n_ipv4ll_get_fd(NIpv4ll *ll, int *fdp) {
        n_acd_get_fd(ll->acd, fdp);
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
 * @ll:         IPv4LL context
 *
 * Return: 0 on successfull dispatch of all pending events. N_IPV4LL_E_PREEPMT
 *         in case there are still more events to be dispatched, or a negative
 *         error code on failure.
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
 * @ll:         IPv4LL context
 * @eventp:     output argument for the event
 *
 * Returns a pointer to the next pending event. The event is still owned by
 * the context, and is only valid until the next call to n_ipv4ll_pop_event()
 * or until the context is freed.
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
 *                             address, and the engine failed to defend it.
 *                             The engine was stopped, the caller must stop
 *                             using the address immediately, and may
 *                             restart the engine to retry.
 *  * N_IPV4LL_EVENT_DOWN:     A network error was detected. The engine was
 *                             stopped, and it is the responsibility of the
 *                             caller to restart it once the network may be
 *                             funcitonal again.
 *
 * Returns: 0 on success, negative error code on failure. The popped event is
 *          returned in @eventp. If no event is pending, NULL is placed in
 *          @eventp and 0 is returned. If an error is returned, @eventp is left
 *          untouched.
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
 * @ll:         IPv4LL context
 *
 * Announce the IP address on the local link, and start defending it.
 *
 * This must be called in response to an N_IPV4LL_EVENT_READY event,
 * and only once the address has been configured on the given interface.
 *
 * Return: 0 on success, or a negative error code on failure.
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
