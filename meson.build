project(
        'n-ipv4ll',
        'c',
        version: '1',
        license: 'Apache',
        default_options: [
                'c_std=c11',
        ],
)
project_description = 'IPv4 Link-Local Address Selection'

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

sub_clist = subproject('c-list')
sub_crbtree = subproject('c-rbtree')
sub_csiphash = subproject('c-siphash')
sub_csundry = subproject('c-sundry')
sub_nacd = subproject('n-acd')

dep_clist = sub_clist.get_variable('libclist_dep')
dep_crbtree = sub_crbtree.get_variable('libcrbtree_dep')
dep_csiphash = sub_csiphash.get_variable('libcsiphash_dep')
dep_csundry = sub_csundry.get_variable('libcsundry_dep')
dep_nacd = sub_nacd.get_variable('libnacd_dep')

subdir('src')
