import glob
import subprocess
import sys

from pybind11 import get_cmake_dir
# Available at setup time due to pyproject.toml
from pybind11.setup_helpers import Pybind11Extension, build_ext
from setuptools import setup

_version_info = subprocess.run(['bash', "./determineVersion.sh"], stdout=subprocess.PIPE)
__version__ = _version_info.stdout.decode("utf-8").rstrip("\n").split("-")[0] if _version_info else "0.0.0"

OBJS = [
    "python/bindings.cpp",
    "src/libnethogs.cpp",
    "src/packet.cpp",
    "src/connection.cpp",
    "src/process.cpp",
    "src/decpcap.c",
    "src/inode2prog.cpp",
    "src/conninode.cpp",
    "src/devices.cpp"
]

FLAGS = [
    "-Wall",
    "-Wextra",
    "-Wno-missing-field-initializers",
    "--std=c++17",
    "-O2",
    "-fPIC",
    '-DVERSION="{}"'.format(__version__)
]
# The main interface is through Pybind11Extension.
# * You can add cxx_std=11/14/17, and then build_ext can be removed.
# * You can set include_pybind11=false to add the include directory yourself,
#   say from a submodule.
#
# Note:
#   Sort input source files if you glob sources to ensure bit-for-bit
#   reproducible builds (https://github.com/pybind/python_example/pull/53)

ext_modules = [
    Pybind11Extension(
        "nethogs",
        sources = OBJS,
        include_dirs = ["src/"],
        extra_compile_args = FLAGS,
        libraries = ["pcap"]
    ),
]

setup(
    name="nethogs",
    version=__version__,
    author="raboof",
    url="https://github.com/raboof/nethogs",
    description="Nethogs python bindings",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    zip_safe=False,
    python_requires=">=3.6",
)
