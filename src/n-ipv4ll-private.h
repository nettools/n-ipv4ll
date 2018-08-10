#pragma once

#include <c-list.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include "n-ipv4ll.h"

typedef struct NIpv4llEventNode NIpv4llEventNode;

#define _cleanup_(_x) __attribute__((__cleanup__(_x)))
#define _public_ __attribute__((__visibility__("default")))

struct NIpv4llConfig {
        int ifindex;
        unsigned int transport;
        uint8_t mac[ETH_ALEN];
        size_t n_mac;
        uint64_t enumeration;
        uint64_t timeout_msecs;
        struct in_addr requested_ip;

        bool enumeration_set : 1;
};

#define N_IPV4LL_CONFIG_NULL(_x) {                                              \
                .transport = _N_IPV4LL_TRANSPORT_N,                             \
                .timeout_msecs = N_ACD_TIMEOUT_RFC5227,                         \
        }

struct NIpv4llEventNode {
        CList ipv4ll_link;
        NIpv4llEvent event;
        uint8_t sender[ETH_ALEN];
        bool is_public : 1;
};

#define N_IPV4LL_EVENT_NODE_NULL(_x) {                                          \
                .ipv4ll_link = C_LIST_INIT((_x).ipv4ll_link),                   \
        }

struct NIpv4ll {
        struct drand48_data enumeration_state;
        CList event_list;
        struct in_addr ip;
        NAcd *acd;
        NAcdProbeConfig *config;
        NAcdProbe *probe;
};

#define N_IPV4LL_NULL(_x) {                                                     \
                .event_list = C_LIST_INIT((_x).event_list),                     \
        }
