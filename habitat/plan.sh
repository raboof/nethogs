pkg_name=nethogs
pkg_origin=core
pkg_maintainer="The Habitat Maintainers <humans@habitat.sh>"
pkg_license=("GPL-2.0")
pkg_description="Linux 'net top' tool"
pkg_upstream_url="https://github.com/raboof/nethogs"

pkg_deps=(
  core/libpcap
  core/ncurses
  core/glibc
  core/gcc-libs
)
pkg_build_deps=(
  core/git
  core/make
  core/gcc
  core/patchelf
)
pkg_bin_dirs=(sbin)


# implement git-based dynamic version strings
pkg_version() {
  if [ -n "${pkg_last_tag}" ]; then
    echo "${pkg_last_version}-git+${pkg_last_tag_distance}.${pkg_commit}"
  else
    echo "${pkg_last_version}-git+${pkg_commit}"
  fi
}


# implement in-git build workflow
do_before() {
  do_default_before

  # configure git repository
  export GIT_DIR="${PLAN_CONTEXT}/../.git"

  # load version information from git
  pkg_commit="$(git rev-parse --short HEAD)"
  pkg_last_tag="$(git describe --tags --abbrev=0 ${pkg_commit} || true 2>/dev/null)"

  if [ -n "${pkg_last_tag}" ]; then
    pkg_last_version=${pkg_last_tag#v}
    pkg_last_tag_distance="$(git rev-list ${pkg_last_tag}..${pkg_commit} --count)"
  else
    pkg_last_version="0.0.0"
  fi

  # initialize pkg_version
  update_pkg_version
}

do_unpack() {
  mkdir "${CACHE_PATH}"
  build_line "Extracting ${GIT_DIR}#${pkg_commit}"
  git archive "${pkg_commit}" | tar -x --directory="${CACHE_PATH}"
}


# implement package's build process
do_build() {
  find . -type f -executable \
    -exec sh -c 'file -i "$1" | grep -q "x-executable; charset=binary"' _ {} \; \
    -print \
    -exec patchelf \
      --interpreter "$(pkg_path_for glibc)/lib/ld-linux-x86-64.so.2" \
      --set-rpath "$(pkg_path_for glibc)/lib:$(pkg_path_for gcc-libs)/lib" \
      {} \;

  make
}

do_install() {
  patchelf \
      --interpreter "$(pkg_path_for glibc)/lib/ld-linux-x86-64.so.2" \
      --set-rpath "${LD_RUN_PATH}" \
      src/nethogs

  PREFIX="${pkg_prefix}" make install
}

do_strip() {
  return 0
}
