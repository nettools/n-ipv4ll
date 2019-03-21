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
#include <fcntl.h>
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
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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

static inline void test_raise_memlock(void) {
        const size_t wanted = 64 * 1024 * 1024;
        struct rlimit get, set;
        int r;

        r = getrlimit(RLIMIT_MEMLOCK, &get);
        assert(!r);

        /* try raising limit to @wanted */
        set.rlim_cur = wanted;
        set.rlim_max = (wanted > get.rlim_max) ? wanted : get.rlim_max;
        r = setrlimit(RLIMIT_MEMLOCK, &set);
        if (r) {
                assert(errno == EPERM);

                /* not privileged to raise limit, so maximize soft limit */
                set.rlim_cur = get.rlim_max;
                set.rlim_max = get.rlim_max;
                r = setrlimit(RLIMIT_MEMLOCK, &set);
                assert(!r);
        }
}

static inline void test_unshare_user_namespace(void) {
        uid_t euid;
        gid_t egid;
        int r, fd;

        /*
         * Enter a new user namespace as root:root.
         */

        euid = geteuid();
        egid = getegid();

        r = unshare(CLONE_NEWUSER);
        assert(r >= 0);

        fd = open("/proc/self/uid_map", O_WRONLY);
        assert(fd >= 0);
        r = dprintf(fd, "0 %d 1\n", euid);
        assert(r >= 0);
        close(fd);

        fd = open("/proc/self/setgroups", O_WRONLY);
        assert(fd >= 0);
        r = dprintf(fd, "deny");
        assert(r >= 0);
        close(fd);

        fd = open("/proc/self/gid_map", O_WRONLY);
        assert(fd >= 0);
        r = dprintf(fd, "0 %d 1\n", egid);
        assert(r >= 0);
        close(fd);
}

static inline void test_setup(void) {
        int r;

        /*
         * Move into a new network and mount namespace both associated
         * with a new user namespace where the current eUID is mapped to
         * 0. Then create a a private instance of /run/netns. This ensures
         * that any network devices or network namespaces are private to
         * the test process.
         */

        test_raise_memlock();
        test_unshare_user_namespace();

        r = unshare(CLONE_NEWNET | CLONE_NEWNS);
        assert(r >= 0);

        r = mount(NULL, "/", "", MS_PRIVATE | MS_REC, NULL);
        assert(r >= 0);

        r = mount(NULL, "/run", "tmpfs", 0, NULL);
        assert(r >= 0);

        r = mkdir("/run/netns", 0755);
        assert(r >= 0);
}
