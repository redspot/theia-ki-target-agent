cmd_/home/yang/omniplay/test/replay_headers/include/linux/netfilter_arp/.install := perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/linux/netfilter_arp /home/yang/omniplay/test/replay_headers/include/linux/netfilter_arp x86 include/linux/netfilter_arp arp_tables.h arpt_mangle.h; perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/linux/netfilter_arp /home/yang/omniplay/test/replay_headers/include/linux/netfilter_arp x86 include/linux/netfilter_arp ; perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/generated/linux/netfilter_arp /home/yang/omniplay/test/replay_headers/include/linux/netfilter_arp x86 include/linux/netfilter_arp ; for F in ; do echo "\#include <asm-generic/$$F>" > /home/yang/omniplay/test/replay_headers/include/linux/netfilter_arp/$$F; done; touch /home/yang/omniplay/test/replay_headers/include/linux/netfilter_arp/.install
