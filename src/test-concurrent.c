/*
 * Test with many concurrent IPv4LL instances on the same network
 * Set up a bridge, connect one veth link per instance, and run
 * IPv4LL on all of them at the same time.
 */
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "test.h"

uint64_t enumerations;

typedef struct Client {
        CRBNode rb;
        int ifindex;
        struct in_addr ip;
        NIpv4ll *ipv4ll;
} Client;

#define CLIENT_INIT(_x) {                               \
                .rb = C_RBNODE_INIT((_x).rb),           \
        }

static void client_new(Client **clientp) {
        Client *client;
        NIpv4llConfig *config;
        int r;
        struct ether_addr mac;

        client = malloc(sizeof(*client));
        assert(client);
        *client = (Client)CLIENT_INIT(*client);

        test_add_bridge_slave(&client->ifindex, &mac);

        r = n_ipv4ll_config_new(&config);
        assert(!r);

        n_ipv4ll_config_set_ifindex(config, client->ifindex);
        n_ipv4ll_config_set_transport(config, N_IPV4LL_TRANSPORT_ETHERNET);
        n_ipv4ll_config_set_mac(config, (const uint8_t *)&mac.ether_addr_octet, ETH_ALEN);
        n_ipv4ll_config_set_timeout(config, 100);
        n_ipv4ll_config_set_enumeration(config, enumerations++);
        n_ipv4ll_config_set_requested_ip(config, (struct in_addr){ htobe32(UINT32_C(0xa9fe0100)) });

        r = n_ipv4ll_new(&client->ipv4ll, config);
        assert(!r);

        *clientp = client;
}

static void client_free(Client *client) {
        assert(!c_rbnode_is_linked(&client->rb));
        n_ipv4ll_free(client->ipv4ll);
        free(client);
}

static void client_set_ip(Client *client, struct in_addr ip) {
        assert(be32toh(ip.s_addr) >= UINT32_C(0xa9fe0100));
        assert(be32toh(ip.s_addr) <= UINT32_C(0xa9fefeff));

        test_add_ip(client->ifindex, &ip);
        client->ip = ip;
}

static int client_compare(CRBTree *t, void *k, CRBNode *rb) {
        struct in_addr *ip = k;
        Client *client = c_container_of(rb, Client, rb);

        if (ip->s_addr < client->ip.s_addr)
                return -1;
        if (ip->s_addr > client->ip.s_addr)
                return 1;

        return 0;
}

static void test_concurrent(unsigned int n_clients) {
        CRBTree client_tree = C_RBTREE_INIT;
        Client *client, *client_safe;
        int r, epoll_fd;

        epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        assert(epoll_fd >= 0);

        for (unsigned int i = 0; i < n_clients; ++i) {
                int fd;

                client_new(&client);

                n_ipv4ll_get_fd(client->ipv4ll, &fd);
                assert(fd >= 0);

                r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &(struct epoll_event){ .events = EPOLLIN, .data = { .ptr = client } });
                assert(r >= 0);
        }

        for (;;) {
                struct epoll_event events[256];
                int n;

                n = epoll_wait(epoll_fd, events, 256, -1);
                assert(n >= 0);

                for (int i = 0; i < n; ++i) {
                        NIpv4llEvent *event;

                        client = events[i].data.ptr;

                        r = n_ipv4ll_dispatch(client->ipv4ll);
                        if (r)
                                assert(r == N_IPV4LL_E_PREEMPTED);

                        do {
                                r = n_ipv4ll_pop_event(client->ipv4ll, &event);
                                if (event) {
                                        CRBNode **slot, *parent;

                                        assert(event->event == N_IPV4LL_EVENT_READY);

                                        slot = c_rbtree_find_slot(&client_tree, client_compare, &client->ip, &parent);
                                        assert(slot);
                                        c_rbtree_add(&client_tree, parent, slot, &client->rb);

                                        client_set_ip(client, event->ready.ip);
                                        r = n_ipv4ll_announce(client->ipv4ll);
                                        assert(r >= 0);

                                        --n_clients;
                                }
                        } while (event);
                }

                if (!n_clients)
                        break;
        }

        c_rbtree_for_each_entry_safe_postorder_unlink(client, client_safe, &client_tree, rb) {
                int fd;

                n_ipv4ll_get_fd(client->ipv4ll, &fd);

                r = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                assert(r >= 0);

                client_free(client);
        }

        close(epoll_fd);
}

int main(int argc, char **argv) {
        int r;

        r = test_setup();
        if (r)
                return r;

        test_create_bridge();

        test_concurrent(16);

        return 0;
}
