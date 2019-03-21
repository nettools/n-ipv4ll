/*
 * Tests for n-ipv4ll API
 * This verifies the visibility and availability of the public API of the
 * n-ipv4ll library.
 */

#include <stdlib.h>
#include "test.h"

static void test_api(void) {
        NIpv4llConfig *config = NULL;
        NIpv4ll *ipv4ll = NULL;
        int r;

        assert(N_IPV4LL_E_PREEMPTED);
        assert(N_IPV4LL_E_INVALID_ARGUMENT);

        assert(N_IPV4LL_TRANSPORT_ETHERNET != _N_IPV4LL_TRANSPORT_N);

        assert(N_IPV4LL_EVENT_READY != _N_IPV4LL_EVENT_N);
        assert(N_IPV4LL_EVENT_DEFENDED != _N_IPV4LL_EVENT_N);
        assert(N_IPV4LL_EVENT_CONFLICT != _N_IPV4LL_EVENT_N);
        assert(N_IPV4LL_EVENT_DOWN != _N_IPV4LL_EVENT_N);

        n_ipv4ll_config_freep(&config);

        r = n_ipv4ll_config_new(&config);
        assert(!r);

        n_ipv4ll_config_set_ifindex(config, 1);
        n_ipv4ll_config_set_transport(config, N_IPV4LL_TRANSPORT_ETHERNET);
        n_ipv4ll_config_set_mac(config, (uint8_t[6]){ }, 6);
        n_ipv4ll_config_set_requested_ip(config, (struct in_addr){ htobe32(UINT32_C(0xa9fe0100)) });
        n_ipv4ll_config_set_timeout(config, 100);
        n_ipv4ll_config_set_enumeration(config, 1);

        {
                NIpv4llEvent *event;
                int fd;

                n_ipv4ll_free(ipv4ll);

                r = n_ipv4ll_new(&ipv4ll, config);
                assert(!r);

                n_ipv4ll_get_fd(ipv4ll, &fd);
                n_ipv4ll_dispatch(ipv4ll);
                n_ipv4ll_pop_event(ipv4ll, &event);
                n_ipv4ll_announce(ipv4ll);

                n_ipv4ll_free(ipv4ll);
                n_ipv4ll_freev(NULL);
        }

        n_ipv4ll_config_free(config);
        n_ipv4ll_config_freev(NULL);
}

int main(int argc, char **argv) {
        test_setup();

        test_api();

        return 0;
}
