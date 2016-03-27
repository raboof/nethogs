#include "conninode.cpp"

local_addr *local_addrs = NULL;
bool bughuntmode = false;

int main() {
  if (!addprocinfo("testfiles/proc_net_tcp")) {
    std::cerr << "Failed to load testfiles/proc_net_tcp" << std::endl;
    return 1;
  }
  if (!addprocinfo("testfiles/proc_net_tcp_big")) {
    std::cerr << "Failed to load testfiles/proc_net_tcp_big" << std::endl;
    return 2;
  }

#if not defined(__APPLE__)
  if (!addprocinfo("/proc/net/tcp")) {
    std::cerr << "Failed to load /proc/net/tcp" << std::endl;
    return 3;
  }
#endif

  return 0;
}
