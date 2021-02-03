#include "conninode.cpp"

local_addr *local_addrs = NULL;
bool bughuntmode = false;

int main() {
  if (!addprocinfo("testfiles/proc_net_tcp", conninode_tcp)) {
    std::cerr << "Failed to load testfiles/proc_net_tcp" << std::endl;
    return 1;
  }
  if (!addprocinfo("testfiles/proc_net_tcp_big", conninode_tcp)) {
    std::cerr << "Failed to load testfiles/proc_net_tcp_big" << std::endl;
    return 2;
  }

#if !defined(__APPLE__) && !defined(__FreeBSD__)
  if (!addprocinfo("/proc/net/tcp", conninode_tcp)) {
    std::cerr << "Failed to load /proc/net/tcp" << std::endl;
    return 3;
  }
#endif

  if (!addprocinfo("testfiles/proc_net_udp", conninode_udp)) {
    std::cerr << "Failed to load testfiles/proc_net_udp" << std::endl;
    return 4;
  }
  if (!addprocinfo("testfiles/proc_net_udp_big", conninode_udp)) {
    std::cerr << "Failed to load testfiles/proc_net_udp_big" << std::endl;
    return 5;
  }

#if !defined(__APPLE__) && !defined(__FreeBSD__)
  if (!addprocinfo("/proc/net/udp", conninode_udp)) {
    std::cerr << "Failed to load /proc/net/udp" << std::endl;
    return 6;
  }
#endif

  return 0;
}
