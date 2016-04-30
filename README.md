Nethogs
=======

[![Build Status](https://travis-ci.org/raboof/nethogs.svg?branch=master)](https://travis-ci.org/raboof/nethogs)

Introduction
------------

NetHogs is a small 'net top' tool. Instead of breaking the traffic down per protocol or per subnet, like most tools do, **it groups bandwidth by process**. 

NetHogs does not rely on a special kernel module to be loaded. If there's suddenly a lot of network traffic, you can fire up NetHogs and immediately see which PID is causing this. This makes it easy to identify programs that have gone wild and are suddenly taking up your bandwidth.

Since NetHogs heavily relies on `/proc`, most features are only available on Linux.
NetHogs can be built on Mac OS X, but it will only show connections, not processes.

Status
------

Nethogs is a mature piece of software included in most Linux distributions.

Ideas for features, as well as [open bugs](https://github.com/raboof/nethogs/issues?q=is%3Aopen+is%3Aissue), can be found on  [issues' label:enhancement](https://github.com/raboof/nethogs/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement).

### Building from source

Nethogs depends on `ncurses` for the text-based interface and `libpcap` for user-level packet capture. So you need to install both **development libraries** before building nethogs. 

#### Debian/Ubuntu

    apt-get install build-essential libncurses5-dev libpcap-dev

#### Yum-based distro's

    yum install gcc-c++ libpcap-devel.x86_64 libpcap.x86_64 ncurses*

#### Getting the source

The master branch is intended to be stable at all times:

    git clone https://github.com/raboof/nethogs

#### Building

After that, simply 

    make
    sudo ./nethogs

#### Installing

    sudo make install
    hash -r
    sudo nethogs

#### Upgrading

When upgrading (or downgrading), you can simply install the new version 'over'
the old one.

#### Uninstalling

If you want to remove Nethogs from your system, you can:

    sudo make uninstall

Coding standards
----------------

We use the [LLVM coding standards](http://llvm.org/docs/CodingStandards.html),
with the exception that we do allow 'return' after 'else' if it makes the code
more readable.

Note to contributors: feel free to request more exceptions and we'll list them 
here.

Not all code currently adheres to this standard. Pull requests fixing style
are welcome, and do write new code in the proper style, but please do not
mix style fixes and new functionality in one pull request.

When writing new code, at least run 'make format' to have clang-format fix
some superficial style aspects.

libnethogs
----------

Apart from the 'nethogs' tool, this codebase now also builds as a 'libnethogs'
library. This is highly experimental, and we expect to break source and binary
compatibility while we look for the right abstraction points. Packaging
libnethogs as an independent package is currently discouraged, as the chance
of different applications successfully using the same libnethogs are slim.

libnethogs is being used in https://github.com/mb-gh/gnethogs

links
-----

Nethogs monitors traffic going to/from a machine, per process. Other tools rather monitor what kind of traffic travels to, from or through a machine, etcetera. I'll try to link to such tools here. By all means open an issue/PR if you know another:

* [nettop](http://srparish.net/scripts/) shows packet types, sorts by either size or number of packets.
* [ettercap](http://ettercap.sf.net/) is a network sniffer/interceptor/logger for ethernet
* [darkstat](http://purl.org/net/darkstat/) breaks down traffic by host, protocol, etc. Geared towards analysing traffic gathered over a longer period, rather than `live' viewing.
* [iftop](http://ex-parrot.com/~pdw/iftop/) shows network traffic by service and host
* [ifstat](http://gael.roualland.free.fr/ifstat/) shows network traffic by interface in a vmstat/iostat-like manner
* [BusyTasks](http://kde-apps.org/content/show.php?content=143833) KDE Plasmoid script using nethogs as a backend
* [gnethogs](https://github.com/mbfoss/gnethogs) GTK-based GUI (work-in-progress)
* [hogwatch](https://github.com/akshayKMR/hogwatch) A bandwidth monitor(per process) with graphs for desktop/web.
 
License
-------

Copyright 2004-2005, 2008, 2010-2012, 2015 Arnout Engelen <arnouten@bzzt.net>
License: nethogs may be redistributed under the terms of the GPLv2 or any 
later version. See the COPYING file for the license text.
