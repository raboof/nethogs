Nethogs
=======

[![Build Status](https://travis-ci.org/raboof/nethogs.svg?branch=master)](https://travis-ci.org/raboof/nethogs)

Introduction
------------

NetHogs is a small 'net top' tool. Instead of breaking the traffic down per protocol or per subnet, like most tools do, **it groups bandwidth by process**. 

![screenshot](/doc/screenshot.png?raw=true)

NetHogs does not rely on a special kernel module to be loaded. If there's suddenly a lot of network traffic, you can fire up NetHogs and immediately see which PID is causing this. This makes it easy to identify programs that have gone wild and are suddenly taking up your bandwidth.

Since NetHogs heavily relies on `/proc`, most features are only available on Linux.
NetHogs can be built on Mac OS X and FreeBSD, but it will only show connections, not processes.

Status
------

Nethogs is a mature piece of software included in most Linux distributions.

Ideas for features, as well as [open bugs](https://github.com/raboof/nethogs/issues?q=is%3Aopen+is%3Aissue), can be found on  [issues' label:enhancement](https://github.com/raboof/nethogs/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement).

### Downloading

You can clone this repo or get a source release from
https://github.com/raboof/nethogs/releases

### Building from source

Nethogs depends on `ncurses` for the text-based interface and `libpcap` for user-level packet capture. So you need to install both **development libraries** before building nethogs. 

#### Debian/Ubuntu

    apt-get install build-essential libncurses5-dev libpcap-dev

#### Yum-based distro's

    yum install gcc-c++ libpcap-devel.x86_64 libpcap.x86_64 "ncurses*"

#### Getting the source

The master branch is intended to be stable at all times:

    git clone https://github.com/raboof/nethogs

#### Building

After that, simply

    make
    sudo ./src/nethogs

#### Installing

##### For all distributions

    sudo make install
    hash -r
    sudo nethogs
    
##### On Debian

    sudo apt-get install checkinstall
    sudo checkinstall -D make install
    sudo dpkg -i nethogs*.deb

#### Upgrading

When upgrading (or downgrading), you can simply install the new version 'over'
the old one.

#### Uninstalling

If you want to remove Nethogs from your system, you can:

    sudo make uninstall

### Running without root

In order to be run by a non-root user, nethogs needs the `cap_net_admin` and `cap_net_raw` capabilities. These can be set on the executable by using the `setcap` command, as follows:

    sudo setcap "cap_net_admin,cap_net_raw+pe" /usr/local/sbin/nethogs

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

Build it with `make libnethogs`, install with `make install_lib` or `make install_dev`.

libnethogs is being used in https://github.com/mb-gh/gnethogs

links
-----

Nethogs monitors traffic going to/from a machine, per process. Other tools rather monitor what kind of traffic travels to, from or through a machine, etcetera. I'll try to link to such tools here. By all means open an issue/PR if you know another:

* [nettop](http://srparish.net/scripts/) shows packet types, sorts by either size or number of packets.
* [ettercap](http://ettercap.sf.net/) is a network sniffer/interceptor/logger for ethernet
* [darkstat](http://purl.org/net/darkstat/) breaks down traffic by host, protocol, etc. Geared towards analysing traffic gathered over a longer period, rather than `live' viewing.
* [iftop](http://ex-parrot.com/~pdw/iftop/) shows network traffic by service and host
* [ifstat](http://gael.roualland.free.fr/ifstat/) shows network traffic by interface in a vmstat/iostat-like manner
* [gnethogs](https://github.com/mbfoss/gnethogs) GTK-based GUI (work-in-progress)
* [nethogs-qt](http://slist.lilotux.net/linux/nethogs-qt/index_en.html) Qt-based GUI
* [hogwatch](https://github.com/akshayKMR/hogwatch) A bandwidth monitor(per process) with graphs for desktop/web.
* [iptraf-ng](https://github.com/iptraf-ng/iptraf-ng) is a console-based network monitoring program for Linux that displays information about IP traffic.
* [nettop (by Emanuele Oriani)](http://nettop.youlink.org/) is a simple process/network usage report for Linux.
* [iptstate](https://www.phildev.net/iptstate/index.shtml) is a top-like interface to your netfilter connection-tracking table.
* [flowtop](http://netsniff-ng.org/) is a top-like netfilter connection tracking tool. 
* [BusyTasks](https://www.pling.com/p/1201835) is a Java-based app using top, iotop and nethogs as backend.
* [bandwhich](https://github.com/imsnif/bandwhich) is a terminal bandwidth utilization tool.
* [sniffer](https://github.com/chenjiandongx/sniffer) is a modern alternative network traffic sniffer.

License
-------

Copyright 2004-2005, 2008, 2010-2012, 2015 Arnout Engelen <arnouten@bzzt.net>
License: nethogs may be redistributed under the terms of the GPLv2 or any 
later version. See the COPYING file for the license text.
