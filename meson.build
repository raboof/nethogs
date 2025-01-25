#
# See COPYING for more information about licensing
#

project('nethogs',
        ['c', 'cpp'],
        default_options : ['warning_level=3',
                           'cpp_std=c++14'],
        version : run_command('./determineVersion.sh').stdout().strip(),
        )

cc = meson.get_compiler('cpp')

#######################################
## Dependencies and flags definition ##
#######################################
# directories
projectinc = [include_directories('.', 'src')]

# flags
c_args = [
  '-DVERSION="' + meson.project_version() + '"'
]

# dependencies
thread_dep = dependency('threads', required: true)
libpcap_dep = dependency('libpcap', required: true)
project_deps = [
  thread_dep,
  libpcap_dep
]

#############################
## Code Compilation        ##
#############################
subdir('src')

#############################
## Pkgconfig definition    ##
#############################
pkgconfig = import('pkgconfig')
pkgconfig_install_dir = join_paths(get_option('libdir'), 'pkgconfig')
pkgconfig.generate(libnethogs,
                   requires: ['libpcap'],
                   version: meson.project_version()
                   )
