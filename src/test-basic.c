/*
 * Test with two conflicts
 * Run the IPv4LL engine when the two first attempts will fail, and the third
 * one succeed. This should just pass through, with a short, random timeout.
 */
#include <stdlib.h>
#include "test.h"

static void test_basic(int ifindex, uint8_t *mac, size_t n_mac) {
        struct pollfd pfds = { .events = POLLIN };
        NIpv4llConfig *config;
        NIpv4ll *acd;
        int r;

        r = n_ipv4ll_config_new(&config);
        assert(!r);

        n_ipv4ll_config_set_ifindex(config, ifindex);
        n_ipv4ll_config_set_transport(config, N_IPV4LL_TRANSPORT_ETHERNET);
        n_ipv4ll_config_set_mac(config, mac, n_mac);
        n_ipv4ll_config_set_enumeration(config, 0);
        n_ipv4ll_config_set_timeout(config, 100);
        n_ipv4ll_config_set_requested_ip(config, (struct in_addr){ htobe32((169 << 24) | (254 << 16) | (1 << 8)) });

        r = n_ipv4ll_new(&acd, config);
        assert(!r);

        n_ipv4ll_config_free(config);

        n_ipv4ll_get_fd(acd, &pfds.fd);

        for (;;) {
                NIpv4llEvent *event;

                r = poll(&pfds, 1, -1);
                assert(r >= 0);

                r = n_ipv4ll_dispatch(acd);
                if (r)
                        assert(r == N_IPV4LL_E_PREEMPTED);

                r = n_ipv4ll_pop_event(acd, &event);
                assert(!r);
                if (event) {
                        assert(event->event == N_IPV4LL_EVENT_READY);
                        assert(event->ready.ip.s_addr == htobe32((169 << 24) | (254 << 16) | (149 << 8) | 109));

                        break;
                }
        }

        n_ipv4ll_free(acd);
}

int main(int argc, char **argv) {
        struct ether_addr mac;
        int r, ifindex;

        r = test_setup();
        if (r)
                return r;

        test_veth_new(&ifindex, &mac, NULL, NULL);
        test_add_child_ip(&(struct in_addr){ htobe32((169 << 24) | (254 << 16) | (1 << 8)) });
        test_add_child_ip(&(struct in_addr){ htobe32((169 << 24) | (254 << 16) | (2 << 8)) });

        test_basic(ifindex, mac.ether_addr_octet, sizeof(mac.ether_addr_octet));

        return 0;
}
