/*
 * Tests for n-ipv4ll API
 * This verifies the visibility and availability of the public API of the
 * n-ipv4ll library.
 */

#undef NDEBUG
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include "n-ipv4ll.h"

static void test_api_constants(void) {
        assert(1 + _N_IPV4LL_E_SUCCESS);
        assert(1 + N_IPV4LL_E_PREEMPTED);
        assert(1 + N_IPV4LL_E_INVALID_ARGUMENT);
        assert(1 + _N_IPV4LL_E_N);

        assert(1 + N_IPV4LL_TRANSPORT_ETHERNET);
        assert(1 + _N_IPV4LL_TRANSPORT_N);

        assert(1 + N_IPV4LL_EVENT_READY);
        assert(1 + N_IPV4LL_EVENT_DEFENDED);
        assert(1 + N_IPV4LL_EVENT_CONFLICT);
        assert(1 + N_IPV4LL_EVENT_DOWN);
        assert(1 + _N_IPV4LL_EVENT_N);
}

static void test_api_types(void) {
        assert(sizeof(NIpv4llEvent*));
        assert(sizeof(NIpv4llConfig*));
        assert(sizeof(NIpv4ll*));
}

static void test_api_functions(void) {
        void *fns[] = {
                (void *)n_ipv4ll_config_new,
                (void *)n_ipv4ll_config_free,
                (void *)n_ipv4ll_config_freep,
                (void *)n_ipv4ll_config_freev,
                (void *)n_ipv4ll_config_set_ifindex,
                (void *)n_ipv4ll_config_set_transport,
                (void *)n_ipv4ll_config_set_mac,
                (void *)n_ipv4ll_config_set_enumeration,
                (void *)n_ipv4ll_config_set_timeout,
                (void *)n_ipv4ll_config_set_requested_ip,

                (void *)n_ipv4ll_new,
                (void *)n_ipv4ll_free,
                (void *)n_ipv4ll_freep,
                (void *)n_ipv4ll_freev,
                (void *)n_ipv4ll_get_fd,
                (void *)n_ipv4ll_dispatch,
                (void *)n_ipv4ll_pop_event,
                (void *)n_ipv4ll_announce,
        };
        size_t i;

        for (i = 0; i < sizeof(fns) / sizeof(*fns); ++i)
                assert(!!fns[i]);
}

int main(int argc, char **argv) {
        test_api_constants();
        test_api_types();
        test_api_functions();
        return 0;
}
