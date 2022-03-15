#include <pybind11/pybind11.h>
#include <pybind11/functional.h>
#include <set>
#include <iostream>

#include "libnethogs.h"

namespace py = pybind11;

//--- for some reason this is a global defined in main.cpp
std::set<pid_t> pidsToWatch;

//--- hacky way to get callbacks working and handle signals
std::function<void(int, NethogsMonitorRecord const *)> empty_callback;
std::function<void(int, NethogsMonitorRecord const *)> loop_callback;
void loop_callback_wrapper(int arg1, NethogsMonitorRecord const *arg2){
  py::gil_scoped_acquire acquire;
  if (PyErr_CheckSignals() != 0) {
    nethogsmonitor_breakloop();
    PyErr_Clear();
  }
  else if (loop_callback) {
    loop_callback(arg1, arg2);
  }
}

int nethogsmonitor_loop_py(
  std::function<void(int, NethogsMonitorRecord const *)> &cb,
  char *filter,
  int to_ms)
{
    int retval;
    loop_callback = cb;
    {
      py::gil_scoped_release release;
      retval = nethogsmonitor_loop(loop_callback_wrapper, filter, to_ms);
    }
    loop_callback = empty_callback;
    return retval;
}

//--- python module binding
PYBIND11_MODULE(nethogs, m) {
    py::class_<NethogsMonitorRecord>(m, "NethogsMonitorRecord")
        .def_readwrite("record_id", &NethogsMonitorRecord::record_id)
        .def_readwrite("name", &NethogsMonitorRecord::name)
        .def_readwrite("pid", &NethogsMonitorRecord::pid)
        .def_readwrite("uid", &NethogsMonitorRecord::uid)
        .def_readwrite("device_name", &NethogsMonitorRecord::device_name)
        .def_readwrite("sent_bytes", &NethogsMonitorRecord::sent_bytes)
        .def_readwrite("recv_bytes", &NethogsMonitorRecord::recv_bytes)
        .def_readwrite("sent_kbs", &NethogsMonitorRecord::sent_kbs)
        .def_readwrite("recv_kbs", &NethogsMonitorRecord::recv_kbs);

    m.def("nethogsmonitor_loop", &nethogsmonitor_loop_py, R"pbdoc(
        Nethogs monitor loop
    )pbdoc");
    m.def("nethogsmonitor_breakloop", &nethogsmonitor_breakloop, R"pbdoc(
        Nethogs monitor loop break
    )pbdoc");

#ifdef VERSION
    m.attr("__version__") = VERSION;
#else
    m.attr("__version__") = "unknown";
#endif

}
