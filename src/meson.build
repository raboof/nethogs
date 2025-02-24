#
# See COPYING for more information about licensing
#

sources = [
    files(
        'connection.cpp',
        'conninode.cpp',
        'decpcap.c',
        'devices.cpp',
        'inode2prog.cpp',
        'packet.cpp',
        'process.cpp',
    ),
]

# --- Executable Compilation ---

if get_option('enable-nethogs-app').enabled()
    app_sources = [files('cui.cpp', 'main.cpp')]

    cursespp_dep = dependency('ncurses++', required: true)
    curses_dep = dependency('ncurses', required: true)

    executable(
        'nethogs',
        [app_sources + sources],
        include_directories: [projectinc],
        cpp_args: c_args,
        c_args: c_args,
        install: true,
        dependencies: [project_deps, cursespp_dep, curses_dep],
    )
endif

# --- Library Compilation ---

if get_option('enable-libnethogs').enabled()
    lib_sources = [files('libnethogs.cpp')]

    libnethogs = shared_library(
        'nethogs' ,
        sources + lib_sources,
        cpp_args: c_args,
        c_args: c_args,
        install: true,
        soversion: meson.project_version(),
        include_directories: [projectinc],
        dependencies: [project_deps],
    )

    libnethogs_dep = declare_dependency(link_with: libnethogs)

    # --- Header Installation ---

    lib_headers = [files('libnethogs.h')]
    install_headers(lib_headers, subdir: 'libnethogs')
endif
