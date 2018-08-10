#pragma once

/*
 * Test Helpers
 * Bunch of helpers to setup the environment for networking tests. This
 * includes net-namespace setups, veth setups, and more.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "n-ipv4ll.h"

int ifname_index = 0;

static inline void test_create_bridge(void) {
        int r;

        r = system("ip link add name bridge type bridge");
        assert(r >= 0);

        r = system("ip link set bridge up");
        assert(r >= 0);
}

static inline void test_add_bridge_slave(int *indexp, struct ether_addr *macp) {
        char *p;
        int r, s;

        r = asprintf(&p, "ip link add eth%d type veth peer name eth%d-slave", ifname_index, ifname_index);
        assert(r >= 0);
        r = system(p);
        assert(r >= 0);
        free(p);

        r = asprintf(&p, "ip link set eth%d up", ifname_index);
        assert(r >= 0);
        r = system(p);
        assert(r >= 0);
        free(p);

        r = asprintf(&p, "ip link set eth%d-slave up", ifname_index);
        assert(r >= 0);
        r = system(p);
        assert(r >= 0);
        free(p);

        r = asprintf(&p, "ip link set eth%d-slave master bridge", ifname_index);
        assert(r >= 0);
        r = system(p);
        assert(r >= 0);
        free(p);

        s = socket(AF_INET, SOCK_DGRAM, 0);
        assert(s >= 0);

        if (indexp) {
                r = asprintf(&p, "eth%d", ifname_index);
                assert(r >= 0);
                *indexp = if_nametoindex(p);
                assert(*indexp > 0);
                free(p);
        }

        if (macp) {
                struct ifreq ifr;

                memset(&ifr, 0, sizeof(ifr));
                r = asprintf(&p, "eth%d", ifname_index);
                assert(r >= 0);
                strcpy(ifr.ifr_name, p);
                free(p);
                r = ioctl(s, SIOCGIFHWADDR, &ifr);
                assert(r >= 0);
                memcpy(macp->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        ++ ifname_index;
}

static inline void test_add_ip(int ifindex, const struct in_addr *addr) {
        char *p, name[IF_NAMESIZE + 1] = {};
        int r;

        p = if_indextoname(ifindex, name);
        assert(p);

        r = asprintf(&p, "ip addr add dev %s %s/16", name, inet_ntoa(*addr));
        assert(r >= 0);

        r = system(p);
        assert(r >= 0);

        free(p);
}

static inline void test_add_child_ip(const struct in_addr *addr) {
        char *p;
        int r;

        r = asprintf(&p, "ip addr add dev veth1 %s/8", inet_ntoa(*addr));
        assert(r >= 0);

        r = system(p);
        assert(r >= 0);

        free(p);
}

static inline void test_veth_cmd(int ifindex, const char *cmd) {
        char *p, name[IF_NAMESIZE + 1] = {};
        int r;

        p = if_indextoname(ifindex, name);
        assert(p);

        r = asprintf(&p, "ip link set %s %s", name, cmd);
        assert(r >= 0);

        /* Again: Ewwww... */
        r = system(p);
        assert(r == 0);

        free(p);
}

static inline void test_veth_new(int *parent_indexp,
                                 struct ether_addr *parent_macp,
                                 int *child_indexp,
                                 struct ether_addr *child_macp) {
        struct ifreq ifr;
        int r, s;

        /* Eww... but it works. */
        r = system("ip link add type veth");
        assert(r == 0);
        r = system("ip link set veth0 up");
        assert(r == 0);
        r = system("ip link set veth1 up");
        assert(r == 0);

        s = socket(AF_INET, SOCK_DGRAM, 0);
        assert(s >= 0);

        if (parent_indexp) {
                *parent_indexp = if_nametoindex("veth0");
                assert(*parent_indexp > 0);
        }

        if (child_indexp) {
                *child_indexp = if_nametoindex("veth1");
                assert(*child_indexp > 0);
        }

        if (parent_macp) {
                memset(&ifr, 0, sizeof(ifr));
                strcpy(ifr.ifr_name, "veth0");
                r = ioctl(s, SIOCGIFHWADDR, &ifr);
                assert(r >= 0);
                memcpy(parent_macp->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        if (child_macp) {
                memset(&ifr, 0, sizeof(ifr));
                strcpy(ifr.ifr_name, "veth1");
                r = ioctl(s, SIOCGIFHWADDR, &ifr);
                assert(r >= 0);
                memcpy(child_macp->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        close(s);
}

static inline int test_setup(void) {
        int r;

        r = unshare(CLONE_NEWNET);
        if (r < 0) {
                assert(errno == EPERM);
                return 77;
        }

        return 0;
}
