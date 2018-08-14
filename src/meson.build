#
# target: libnipv4ll.so
#

libnipv4ll_symfile = join_paths(meson.current_source_dir(), 'libnipv4ll.sym')

libnipv4ll_deps = [
        dep_clist,
        dep_nacd,
]

libnipv4ll_private = static_library(
        'nipv4ll-private',
        [
                'n-ipv4ll.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common'
        ],
        dependencies: libnipv4ll_deps,
        pic: true,
)

libnipv4ll_shared = shared_library(
        'nipv4ll',
        objects: libnipv4ll_private.extract_all_objects(),
        dependencies: libnipv4ll_deps,
        install: not meson.is_subproject(),
        soversion: 0,
        link_depends: libnipv4ll_symfile,
        link_args: [
                '-Wl,--no-undefined',
                '-Wl,--version-script=@0@'.format(libnipv4ll_symfile)
        ],
)

libnipv4ll_dep = declare_dependency(
        include_directories: include_directories('.'),
        link_with: libnipv4ll_private,
        dependencies: libnipv4ll_deps,
        version: meson.project_version(),
)

if not meson.is_subproject()
        install_headers('n-ipv4ll.h')

        mod_pkgconfig.generate(
                libraries: libnipv4ll_shared,
                version: meson.project_version(),
                name: 'libnipv4ll',
                filebase: 'libnipv4ll',
                description: project_description,
        )
endif

#
# target: test-*
#

test_api = executable('test-api', ['test-api.c'], link_with: libnipv4ll_shared)
test('API Symbol Visibility', test_api)

test_basic = executable('test-basic', ['test-basic.c'], dependencies: libnipv4ll_dep)
test('Basic API Behavior', test_basic)

test_concurrent = executable('test-concurrent', ['test-concurrent.c'], dependencies: [dep_crbtree, libnipv4ll_dep])
test('Concurrent IPv4LL probing', test_concurrent)
