cmd_/home/yang/omniplay/test/replay_headers/include/linux/sunrpc/.install := perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/linux/sunrpc /home/yang/omniplay/test/replay_headers/include/linux/sunrpc x86 include/linux/sunrpc debug.h; perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/linux/sunrpc /home/yang/omniplay/test/replay_headers/include/linux/sunrpc x86 include/linux/sunrpc ; perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/generated/linux/sunrpc /home/yang/omniplay/test/replay_headers/include/linux/sunrpc x86 include/linux/sunrpc ; for F in ; do echo "\#include <asm-generic/$$F>" > /home/yang/omniplay/test/replay_headers/include/linux/sunrpc/$$F; done; touch /home/yang/omniplay/test/replay_headers/include/linux/sunrpc/.install
