## Python stuff
This directory contains the code that wraps `libnethogs` into a python module.

### To build + install
Install dependencies:
``` bash
apt-get install build-essential libncurses5-dev libpcap-dev pybind11-dev
```
All the code is compiled through the [pybind11 setuptools building system](https://pybind11.readthedocs.io/en/stable/compiling.html). So to build and install you just need to do:
``` bash
### if you have the code cloned locally
pip install .
```
Or:
``` bash
### if you can't bother to clone the repo yourself
pip install git+https://github.com/raboof/nethogs.git
```

### To use
``` python
import nethogs
import threading

def callback(action: int, record: nethogs.NethogsMonitorRecord) -> None:
    do_whatever_with_record(record)
    return
    
th = threading.Thread(target=nethogs.nethogsmonitor_loop, args(callback, filter, to_ms))
th.start()
do_whatever_you_need_to_do()
nethogs.nethogsmonitor_breakloop()
th.join()
```

### Caveats
- **Ideally this should not be run in the main thread**, stopping the nethogsmonitor_loop with a SIGINT or SIGTERM is a bit hacky and could break things.
- Only one instance of the loop can be run at a time, callbacks would get completely messed up if more than one is run. I believe nethogs only allows one at a time anyways.
- There is no way of setting pidsToWatch, but it is not difficult to implement if anyone wants to do it :)
- The package version is set in setup.py using the script determineVersion.sh, but it is very hacky as a PEP compatible string is needed. Something stronger should be implemented, ideally using the regex module.

## Extra stuff
The script `python-wrapper.py` used to be in a contrib directory. This script loads the libnethogs library directly, which you shouldn't really do anyways. The way of using nethogs in python by the `python-wrapper.py` is now deprecated. I'm just leaving it here to not destroy the previous contribution. This is the original comment that **raboof** made about the `python-wrapper.py` and the `contrib` directory:
```
This folder contains user-contributed scripts.

The Nethogs project does not make claims about the quality of the scripts, maintains
them in any way, or necessarily think they're a good idea in the first place :).
```
