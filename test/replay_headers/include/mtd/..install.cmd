cmd_/home/yang/omniplay/test/replay_headers/include/mtd/.install := perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/mtd /home/yang/omniplay/test/replay_headers/include/mtd x86 include/mtd inftl-user.h mtd-abi.h mtd-user.h nftl-user.h ubi-user.h; perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/mtd /home/yang/omniplay/test/replay_headers/include/mtd x86 include/mtd ; perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/include/generated/mtd /home/yang/omniplay/test/replay_headers/include/mtd x86 include/mtd ; for F in ; do echo "\#include <asm-generic/$$F>" > /home/yang/omniplay/test/replay_headers/include/mtd/$$F; done; touch /home/yang/omniplay/test/replay_headers/include/mtd/.install
