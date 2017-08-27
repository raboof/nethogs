#!/usr/bin/env python
"""
This is a Python 3 demo of how to interact with the Nethogs library via Python.
The Nethogs library operates via a callback. The callback implemented here just
formats the data it receives and prints it to stdout. This must be run as root
(`sudo python3 python-wrapper.py`).

The code is multi-threaded to allow it to respond to SIGTERM and SIGINT
(Ctrl+C).  In single-threaded mode, while waiting in the Nethogs monitor loop,
this Python code won't receive Ctrl+C until network activity occurs and the
callback is executed. By using 2 threads, we can have the main thread listen for
SIGINT while the secondary thread is blocked in the monitor loop.

By Philip Semanchuk (psemanchuk@caktusgroup.com) November 2016
Updated to use a class and argparse by Jason Antman (jason@jasonantman.com),
 August 2017
Copyright waived; released into public domain as is.
"""

import sys
import ctypes
import signal
import threading
import argparse
import logging

FORMAT = "[%(asctime)s %(levelname)s] %(message)s"
logging.basicConfig(level=logging.WARNING, format=FORMAT)
logger = logging.getLogger()

#: Name of the libnethogs DLL to load (can be overridden by CLI option).
#: LIBRARY_NAME has to be exact, although it doesn't need to include the full
#: path. The version tagged as 0.8.5 builds a library with this name; It can be
#: downloaded from: https://github.com/raboof/nethogs/archive/v0.8.5.tar.gz
LIBRARY_NAME = 'libnethogs.so.0.8.5'


class Action(object):
    """
    Possible callback actions from libnethogs.h

    See: https://github.com/raboof/nethogs/blob/master/src/libnethogs.h

    Possible actions are NETHOGS_APP_ACTION_SET & NETHOGS_APP_ACTION_REMOVE
    Action REMOVE is sent when nethogs decides a connection or a process has
    died. There are two timeouts defined, PROCESSTIMEOUT (150 seconds) and
    CONNTIMEOUT (50 seconds). AFAICT, the latter trumps the former so we see
    a REMOVE action after ~45-50 seconds of inactivity.
    """

    #: Action value for updating statistics for a Process.
    SET = 1

    #: Action value for removing a timed-out Process.
    REMOVE = 2

    #: Dict mapping action numeric values to string descriptions.
    MAP = {SET: 'SET', REMOVE: 'REMOVE'}


class LoopStatus(object):
    """Return codes from nethogsmonitor_loop()"""

    #: Return code for OK status.
    OK = 0

    #: Return code for failure status.
    FAILURE = 1

    #: Return code for status when no devices were found for capture.
    NO_DEVICE = 2

    #: Dict mapping numeric status values to string descriptions.
    MAP = {OK: 'OK', FAILURE: 'FAILURE', NO_DEVICE: 'NO_DEVICE'}


class NethogsMonitorRecord(ctypes.Structure):
    """
    ctypes version of the struct of the same name from libnethogs.h

    The sent/received KB/sec values are averaged over 5 seconds; see PERIOD
    in nethogs.h. sent_bytes and recv_bytes are a running total.

    See: https://github.com/raboof/nethogs/blob/master/src/nethogs.h
    """
    _fields_ = (
        ('record_id', ctypes.c_int),
        ('name', ctypes.c_char_p),
        ('pid', ctypes.c_int),
        ('uid', ctypes.c_uint32),
        ('device_name', ctypes.c_char_p),
        ('sent_bytes', ctypes.c_uint64),
        ('recv_bytes', ctypes.c_uint64),
        ('sent_kbs', ctypes.c_float),
        ('recv_kbs', ctypes.c_float),
    )

#: ctypes wrapper for the type of the libnethogs callback function
CALLBACK_FUNC_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.POINTER(NethogsMonitorRecord)
)


class HogWatcher(threading.Thread):

    def __init__(self, lib, dev_names=[], filter=None):
        """
        Thread to watch and react to nethogs data updates.

        :param lib: nethogs library instance
        :type lib: ctypes.CDLL
        :param dev_names: list of device names to track
        :type dev_names: list
        :param filter: pcap-filter format packet capture filter expression
        :type filter: str
        """
        threading.Thread.__init__(self)
        self._lib = lib
        self._lib.nethogsmonitor_loop.restype = ctypes.c_int
        self._dev_names = dev_names
        self._filter = filter
        logger.debug('Initializing HogWatcher')
        if len(self._dev_names) > 0:
            logger.info('Will only monitor devices: %s', self._dev_names)

    @property
    def dev_args(self):
        """
        Return the appropriate ctypes arguments for a device name list, to pass
        to libnethogs ``nethogsmonitor_loop_devices``. The return value is a
        2-tuple of devc (``ctypes.c_int``) and devicenames (``ctypes.POINTER``)
        to an array of ``ctypes.c_char``).

        :param devnames: list of device names to monitor
        :type devnames: list
        :return: 2-tuple of devc, devicenames ctypes arguments
        :rtype: tuple
        """
        devc = len(self._dev_names)
        if devc == 0:
            return ctypes.c_int(0), None
        devnames_type = ctypes.c_char_p * devc
        devnames_arg = devnames_type()
        for idx, val in enumerate(self._dev_names):
            devnames_arg[idx] = (val + chr(0)).encode('ascii')
        return ctypes.c_int(devc), ctypes.cast(
            devnames_arg, ctypes.POINTER(ctypes.c_char_p)
        )

    def run(self):
        """
        Create a type for my callback func. The callback func returns void
        (None), and accepts as params an int and a pointer to a
        NethogsMonitorRecord instance. The params and return type of the
        callback function are mandated by nethogsmonitor_loop().
        See libnethogs.h.
        """
        devc, devicenames = self.dev_args
        filter_arg = self._filter
        if filter_arg is not None:
            logger.info('Restricting capture with filter: %s', filter_arg)
            filter_arg = ctypes.c_char_p(filter_arg.encode('ascii'))
        rc = self._lib.nethogsmonitor_loop_devices(
            CALLBACK_FUNC_TYPE(self._callback),
            filter_arg,
            devc,
            devicenames,
            False
        )
        if rc != LoopStatus.OK:
            logger.error(
                'nethogsmonitor_loop returned %s', LoopStatus.MAP[rc]
            )
        else:
            logger.warning('exiting monitor loop')

    def _callback(self, action, data):
        """
        Callback fired when libnethogs loop has a data update.

        :param action: The action type; attribute on Action class.
        :type action: int
        :param data: Updated NethogsMonitorRecord containing latest data
        :type data: NethogsMonitorRecord
        """
        action_name = Action.MAP.get(action, 'Unknown')
        print(
            'Action: {act}\nRecord id: {rec}\nName: {name}\nPID: {pid}\n'
            'UID: {uid}\nDevice name: {devname}\nSent/Recv bytes: {sent_b} /'
            ' {recv_b}\nSent/Recv kbs: {sent_k} / {recv_k}\n{spacer}'.format(
                act=action_name, rec=data.contents.record_id,
                name=data.contents.name, pid=data.contents.pid,
                uid=data.contents.uid,
                devname=data.contents.device_name.decode('ascii'),
                sent_b=data.contents.sent_bytes,
                recv_b=data.contents.recv_bytes,
                sent_k=data.contents.sent_kbs, recv_k=data.contents.recv_kbs,
                spacer=('-' * 30)
            )
        )


def parse_args(argv):
    """
    parse arguments/options
    """
    p = argparse.ArgumentParser(
        description='example Python libnethogs wrapper script'
    )
    p.add_argument('-L', '--library-name', dest='libname', action='store',
                   type=str, default=LIBRARY_NAME,
                   help='Override library name from default of "%s" (for '
                        'testing locally-built modified library)'
                        '' % LIBRARY_NAME)
    p.add_argument('-f', '--filter', dest='filter', action='store',
                   type=str, default=None,
                   help='EXPERIMENTAL - pcap packet filter expression to limit '
                        'the capture (see man pcap-filter); This feature may '
                        'be removed or changed in a future release.')
    p.add_argument('-d', '--device', dest='devices', action='append',
                   default=[],
                   help='device names to track (specify multiple times)')
    p.add_argument('-v', '--verbose', dest='verbose', action='count', default=0,
                   help='verbose output. specify twice for debug-level output.')
    args = p.parse_args(argv)
    return args


def set_log_info():
    """set logger level to INFO"""
    set_log_level_format(logging.INFO,
                         '%(asctime)s %(levelname)s:%(name)s:%(message)s')


def set_log_debug():
    """set logger level to DEBUG, and debug-level output format"""
    set_log_level_format(
        logging.DEBUG,
        "%(asctime)s [%(levelname)s %(filename)s:%(lineno)s - "
        "%(name)s.%(funcName)s() ] %(message)s"
    )


def set_log_level_format(level, format):
    """
    Set logger level and format.

    :param level: logging level; see the :py:mod:`logging` constants.
    :type level: int
    :param format: logging formatter format string
    :type format: str
    """
    formatter = logging.Formatter(fmt=format)
    logger.handlers[0].setFormatter(formatter)
    logger.setLevel(level)

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    # set logging level
    if args.verbose > 1:
        set_log_debug()
    elif args.verbose == 1:
        set_log_info()

    logger.debug('Loading DLL: %s', args.libname)
    lib = ctypes.CDLL(args.libname)

    def signal_handler(signal, frame):
        logger.error('SIGINT received; requesting exit from monitor loop.')
        lib.nethogsmonitor_breakloop()

    logger.debug('Setting up signal handlers for SIGINT and SIGTERM')
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.debug('Creating monitor thread')
    monitor_thread = HogWatcher(lib, args.devices, args.filter)
    logger.debug('Starting monitor thread')
    monitor_thread.start()

    done = False
    while not done:
        monitor_thread.join(0.3)
        done = not monitor_thread.is_alive()
