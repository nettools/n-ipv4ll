n-ipv4ll
========

IPv4 Link-Local Address Selection

The n-ipv4ll project implements link-local address selection for IPv4 as
defined in RFC-3927. The implementation is linux-only and relies on modern
linux kernel behavior and features.

### Project

 * **Website**: <https://nettools.github.io/n-ipv4ll>
 * **Bug Tracker**: <https://github.com/nettools/n-ipv4ll/issues>
 * **Mailing-List**: <https://groups.google.com/forum/#!forum/nettools-devel>

### Requirements

The requirements for this project are:

 * `Linux kernel >= 3.19`
 * `libc` (e.g., glibc >= 2.16)

At build-time, the following software is required:

 * `meson >= 0.41`
 * `pkg-config >= 0.29`

### Build

To build this project, run:

```sh
mkdir build
cd build
meson setup ..
ninja
meson test
ninja install
```

### Repository:

 - **web**:   <https://github.com/nettools/n-ipv4ll>
 - **https**: `https://github.com/nettools/n-ipv4ll.git`
 - **ssh**:   `git@github.com:nettools/n-ipv4ll.git`

### License:

 - **Apache-2.0** OR **LGPL-2.1-or-later**
 - See AUTHORS file for details.
