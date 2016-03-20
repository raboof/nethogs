Nethogs
=======

[![Build Status](https://travis-ci.org/raboof/nethogs.svg?branch=master)](https://travis-ci.org/raboof/nethogs)

http://raboof.github.io/nethogs

Introduction
------------

NetHogs is a small 'net top' tool. Instead of breaking the traffic down per protocol or per subnet, like most tools do, **it groups bandwidth by process**. 

NetHogs does not rely on a special kernel module to be loaded. If there's suddenly a lot of network traffic, you can fire up NetHogs and immediately see which PID is causing this. This makes it easy to indentify programs that have gone wild and are suddenly taking up your bandwidth.

Since NetHogs heavily relies on `/proc`, some functionalities are only available on Linux.

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

#### General

After that, simply 

    make && sudo make install

Coding standards
----------------

Can anyone recommend a sensible set? :)

For now:
* '{' 
 * on a new line for function definitions
 * on a new line for enums
 * on the same line for conditionals/loops 
 * omitted when possible
* use tab for indentation
* use doxygen/javadoc-style comments.
 * for multiline doxygen docs, add a newline after '/**'
* case
 * classes: camelcased, start uppercase
 * enums: camelcased, start uppercase
 * functions: camelcased, start lowercase
 * local variables: camelcased, start lowercase

libnethogs
----------

Apart from the 'nethogs' tool, this codebase now also builds as a 'libnethogs'
library. This is highly experimental, and we expect to break source and binary
compatibility while we look for the right abstraction points. Packaging
libnethogs as an independent package is currently discouraged, as the chance
of different applications successfully using the same libnethogs are slim.

libnethogs is being used in https://github.com/mb-gh/gnethogs

License
-------

Copyright 2004-2005, 2008, 2010-2012, 2015 Arnout Engelen <arnouten@bzzt.net>
License: nethogs may be redistributed under the terms of the GPLv2 or any 
later version. See the COPYING file for the license text.
