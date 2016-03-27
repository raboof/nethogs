#include "conninode.cpp"

local_addr *local_addrs = NULL;

int main() {
  if (!addprocinfo("testfiles/proc_net_tcp")) {
    std::cerr << "Failed to load testfiles/proc_net_tcp" << std::endl;
    return 1;
  }
  if (!addprocinfo("testfiles/proc_net_tcp_big")) {
    std::cerr << "Failed to load testfiles/proc_net_tcp_big" << std::endl;
    return 2;
  }

#if defined(__APPLE__)
  if (!addprocinfo("net.inet.tcp.pcblist")) {
    std::cerr << "Failed to load net.inet.tcp.pcblist" << std::endl;
    return 3;
  }
#else
  if (!addprocinfo("/proc/net/tcp")) {
    std::cerr << "Failed to load /proc/net/tcp" << std::endl;
    return 4;
  }
#endif

  return 0;
}
