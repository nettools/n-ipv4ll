# n-ipv4ll - IPv4 Link-Local Address Selection

## CHANGES WITH 2:

        * Pull in latest n-acd updates (up to n-acd-2).

        * Document the API with in-source comments. This includes documentation
          for all API entry points as well as an introduction.

        * Make the test-suite more robust and allow running as non-root.

        Contributions from: David Rheinsberg

        - Tübingen, 2019-03-21

## CHANGES WITH 1:

        * Initial release of n-ipv4ll. This project provides the libnipv4ll
          library, implementing IPv4 Link-Local Address Selection as defined in
          RFC-3927.
          The library is based on n-acd, but currently has its own private
          version bundled. Once n-acd is a valid dependency to rely on, the
          bundling will be canceled.

        * The n-ipv4ll project is now available under the conditions of the
          ASL-2.0 (as it was before) *and* optionally the LGPL-2.1+.

        Contributions from: David Herrmann, Tom Gundersen

        - Tübingen, 2018-08-15
