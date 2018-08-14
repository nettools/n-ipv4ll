#pragma once

/*
 * IPv4 Link-Local Address Selection
 *
 * This is the public header of the n-ipv4ll library, implementing Dynamic IPv4
 * Link-Local Address Selection as described in RFC-3927. This header
 * defines the public API and all entry points of n-ipv4ll.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct NIpv4ll NIpv4ll;
typedef struct NIpv4llConfig NIpv4llConfig;
typedef struct NIpv4llEvent NIpv4llEvent;

enum {
        _N_IPV4LL_E_SUCCESS,

        N_IPV4LL_E_PREEMPTED,
        N_IPV4LL_E_INVALID_ARGUMENT,

        _N_IPV4LL_E_N,
};

enum {
        N_IPV4LL_TRANSPORT_ETHERNET,
        _N_IPV4LL_TRANSPORT_N,
};

enum {
        N_IPV4LL_EVENT_READY,
        N_IPV4LL_EVENT_DEFENDED,
        N_IPV4LL_EVENT_CONFLICT,
        N_IPV4LL_EVENT_DOWN,
        _N_IPV4LL_EVENT_N,
};

typedef struct NIpv4llEvent {
        unsigned int event;
        union {
                struct {
                        struct in_addr ip;
                } ready;
                struct {
                } down;
                struct {
                        uint8_t *sender;
                        size_t n_sender;
                } defended, conflict;
        };
} NIpv4llEvent;

/* configs */

int n_ipv4ll_config_new(NIpv4llConfig **configp);
NIpv4llConfig *n_ipv4ll_config_free(NIpv4llConfig *config);

void n_ipv4ll_config_set_ifindex(NIpv4llConfig *config, int ifindex);
void n_ipv4ll_config_set_transport(NIpv4llConfig *config, unsigned int transport);
void n_ipv4ll_config_set_mac(NIpv4llConfig *config, const uint8_t *mac, size_t n_mac);
void n_ipv4ll_config_set_enumeration(NIpv4llConfig *config, uint64_t enumeration);
void n_ipv4ll_config_set_timeout(NIpv4llConfig *config, uint64_t msecs);
void n_ipv4ll_config_set_requested_ip(NIpv4llConfig *config, struct in_addr ip);

/* contexts */

int n_ipv4ll_new(NIpv4ll **ipv4llp, NIpv4llConfig *config);
NIpv4ll *n_ipv4ll_free(NIpv4ll *ipv4ll);

void n_ipv4ll_get_fd(NIpv4ll *ipv4ll, int *fdp);
int n_ipv4ll_dispatch(NIpv4ll *ipv4ll);
int n_ipv4ll_pop_event(NIpv4ll *ipv4ll, NIpv4llEvent **eventp);

int n_ipv4ll_announce(NIpv4ll *ipv4ll);

/* inline helpers */

static inline void n_ipv4ll_config_freep(NIpv4llConfig **configp) {
        if (*configp)
                n_ipv4ll_config_free(*configp);
}

static inline void n_ipv4ll_config_freev(NIpv4llConfig *config) {
        n_ipv4ll_config_free(config);
}

static inline void n_ipv4ll_freep(NIpv4ll **ipv4llp) {
        if (*ipv4llp)
                n_ipv4ll_free(*ipv4llp);
}

static inline void n_ipv4ll_freev(NIpv4ll *ipv4ll) {
        n_ipv4ll_free(ipv4ll);
}

#ifdef __cplusplus
}
#endif
