cmd_/home/yang/omniplay/test/replay_headers/include/asm/.install := perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/arch/x86/include/asm /home/yang/omniplay/test/replay_headers/include/asm x86 include/asm a.out.h auxvec.h bitsperlong.h boot.h bootparam.h byteorder.h debugreg.h e820.h errno.h fcntl.h hw_breakpoint.h hyperv.h ioctl.h ioctls.h ipcbuf.h ist.h kvm.h kvm_para.h ldt.h mce.h mman.h msgbuf.h msr-index.h msr.h mtrr.h param.h poll.h posix_types.h posix_types_32.h posix_types_64.h posix_types_x32.h prctl.h processor-flags.h ptrace-abi.h ptrace.h resource.h sembuf.h setup.h shmbuf.h sigcontext.h sigcontext32.h siginfo.h signal.h socket.h sockios.h stat.h statfs.h swab.h termbits.h termios.h types.h ucontext.h unistd.h vm86.h vsyscall.h; perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/arch/x86/include/asm /home/yang/omniplay/test/replay_headers/include/asm x86 include/asm ; perl scripts/headers_install.pl /home/yang/omniplay/linux-lts-quantal-3.5.0/arch/x86/include/generated/asm /home/yang/omniplay/test/replay_headers/include/asm x86 include/asm unistd_32.h unistd_64.h unistd_x32.h; for F in ; do echo "\#include <asm-generic/$$F>" > /home/yang/omniplay/test/replay_headers/include/asm/$$F; done; touch /home/yang/omniplay/test/replay_headers/include/asm/.install
