import ctypes
import signal
import datetime
import threading

# This is a Python 3 demo of how to interact with the Nethogs library via Python. The Nethogs
# library operates via a callback. The callback implemented here just formats the data it receives
# and prints it to stdout. This must be run as root (`sudo python3 python-wrapper.py`).
# By Philip Semanchuk (psemanchuk@caktusgroup.com) November 2016
# Copyright waived; released into public domain as is.

# The code is multi-threaded to allow it to respond to SIGTERM and SIGINT (Ctrl+C).  In single-
# threaded mode, while waiting in the Nethogs monitor loop, this Python code won't receive Ctrl+C
# until network activity occurs and the callback is executed. By using 2 threads, we can have the
# main thread listen for SIGINT while the secondary thread is blocked in the monitor loop.


# LIBRARY_NAME has to be exact, although it doesn't need to include the full path.
# The version tagged as 0.8.5 (download link below) builds a library with this name.
# https://github.com/raboof/nethogs/archive/v0.8.5.tar.gz
LIBRARY_NAME = 'libnethogs.so.0.8.5'

# Here are some definitions from libnethogs.h
# https://github.com/raboof/nethogs/blob/master/src/libnethogs.h
# Possible actions are NETHOGS_APP_ACTION_SET & NETHOGS_APP_ACTION_REMOVE
# Action REMOVE is sent when nethogs decides a connection or a process has died. There are two
# timeouts defined, PROCESSTIMEOUT (150 seconds) and CONNTIMEOUT (50 seconds). AFAICT, the latter
# trumps the former so we see a REMOVE action after ~45-50 seconds of inactivity.
class Action():
    SET = 1
    REMOVE = 2

    MAP = {SET: 'SET', REMOVE: 'REMOVE'}

class LoopStatus():
    """Return codes from nethogsmonitor_loop()"""
    OK = 0
    FAILURE = 1
    NO_DEVICE = 2

    MAP = {OK: 'OK', FAILURE: 'FAILURE', NO_DEVICE: 'NO_DEVICE'}

# The sent/received KB/sec values are averaged over 5 seconds; see PERIOD in nethogs.h.
# https://github.com/raboof/nethogs/blob/master/src/nethogs.h#L43
# sent_bytes and recv_bytes are a running total
class NethogsMonitorRecord(ctypes.Structure):
    """ctypes version of the struct of the same name from libnethogs.h"""
    _fields_ = (('record_id', ctypes.c_int),
                ('name', ctypes.c_char_p),
                ('pid', ctypes.c_int),
                ('uid', ctypes.c_uint32),
                ('device_name', ctypes.c_char_p),
                ('sent_bytes', ctypes.c_uint32),
                ('recv_bytes', ctypes.c_uint32),
                ('sent_kbs', ctypes.c_float),
                ('recv_kbs', ctypes.c_float),
                )


def signal_handler(signal, frame):
    print('SIGINT received; requesting exit from monitor loop.')
    lib.nethogsmonitor_breakloop()


def run_monitor_loop(lib):
    # Create a type for my callback func. The callback func returns void (None), and accepts as
    # params an int and a pointer to a NethogsMonitorRecord instance.
    # The params and return type of the callback function are mandated by nethogsmonitor_loop().
    # See libnethogs.h.
    CALLBACK_FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int,
                                          ctypes.POINTER(NethogsMonitorRecord))

    rc = lib.nethogsmonitor_loop(CALLBACK_FUNC_TYPE(network_activity_callback))

    if rc != LoopStatus.OK:
        print('nethogsmonitor_loop returned {}'.format(LoopStatus.MAP[rc]))
    else:
        print('exiting monitor loop')


def network_activity_callback(action, data):
    print(datetime.datetime.now().strftime('@%H:%M:%S.%f'))

    # Action type is either SET or REMOVE. I have never seen nethogs send an unknown action
    # type, and I don't expect it to do so.
    action_type = Action.MAP.get(action, 'Unknown')

    print('Action: {}'.format(action_type))
    print('Record id: {}'.format(data.contents.record_id))
    print('Name: {}'.format(data.contents.name))
    print('PID: {}'.format(data.contents.pid))
    print('UID: {}'.format(data.contents.uid))
    print('Device name: {}'.format(data.contents.device_name.decode('ascii')))
    print('Sent/Recv bytes: {} / {}'.format(data.contents.sent_bytes, data.contents.recv_bytes))
    print('Sent/Recv kbs: {} / {}'.format(data.contents.sent_kbs, data.contents.recv_kbs))
    print('-' * 30)

#############       Main begins here      ##############

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

lib = ctypes.CDLL(LIBRARY_NAME)

monitor_thread = threading.Thread(target=run_monitor_loop, args=(lib,))

monitor_thread.start()

done = False
while not done:
    monitor_thread.join(0.3)
    done = not monitor_thread.is_alive()
