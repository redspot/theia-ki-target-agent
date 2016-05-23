# config.make.  Generated from config.make.in by configure.
# Don't edit this file.  Put configuration parameters in configparms instead.

version = 2.15
release = stable

# Installation prefixes.
install_root = $(DESTDIR)
prefix = /home/yang/omniplay/eglibc-2.15/prefix
exec_prefix = ${prefix}
datadir = ${datarootdir}
libdir = ${exec_prefix}/lib
slibdir = 
localedir = 
sysconfdir = ${prefix}/etc
libexecdir = ${exec_prefix}/libexec
rootsbindir = 
infodir = ${datarootdir}/info
includedir = ${prefix}/include
datarootdir = ${prefix}/share

# Should we use and build ldconfig?
use-ldconfig = yes

# Maybe the `ldd' script must be rewritten.
ldd-rewrite-script = sysdeps/unix/sysv/linux/ldd-rewrite.sed

# System configuration.
config-machine = i686
base-machine = i386
config-vendor = pc
config-os = linux-gnu
config-sysdirs =  sysdeps/i386/elf nptl/sysdeps/unix/sysv/linux/i386/i686 sysdeps/unix/sysv/linux/i386/i686 nptl/sysdeps/unix/sysv/linux/i386 sysdeps/unix/sysv/linux/i386 nptl/sysdeps/unix/sysv/linux nptl/sysdeps/pthread sysdeps/pthread ports/sysdeps/unix/sysv/linux sysdeps/unix/sysv/linux sysdeps/gnu sysdeps/unix/common sysdeps/unix/mman sysdeps/unix/inet sysdeps/unix/sysv/i386 nptl/sysdeps/unix/sysv ports/sysdeps/unix/sysv sysdeps/unix/sysv sysdeps/unix/i386 nptl/sysdeps/unix ports/sysdeps/unix sysdeps/unix sysdeps/posix sysdeps/i386/i686/fpu sysdeps/i386/i686/multiarch nptl/sysdeps/i386/i686 sysdeps/i386/i686 sysdeps/i386/i486 nptl/sysdeps/i386/i486 sysdeps/i386/fpu nptl/sysdeps/i386 sysdeps/i386 sysdeps/wordsize-32 sysdeps/ieee754/ldbl-96 sysdeps/ieee754/dbl-64 sysdeps/ieee754/flt-32 sysdeps/ieee754 sysdeps/generic/elf sysdeps/generic
cflags-cpu = 
asflags-cpu = 

config-cflags-sse4 = yes
config-cflags-avx = yes
config-cflags-novzeroupper = yes
config-asflags-i686 = yes

defines =  -D_LIBC_REENTRANT
sysincludes = 
c++-sysincludes = 
all-warnings = 

elf = yes
have-z-combreloc = yes
have-z-execstack = yes
have-initfini = 
have-Bgroup = yes
have-as-needed = yes
libgcc_s_suffix = 
need-nopic-initfini = 
with-fp = yes
old-glibc-headers = no
unwind-find-fde = yes
have-cpp-asm-debuginfo = yes
enable-check-abi = no
have-forced-unwind = yes
have-fpie = yes
have-mfma4 = yes
gnu89-inline-CFLAGS = -fgnu89-inline
have-ssp = yes
have-selinux = no
have-libaudit = 
have-libcap = 
have-cc-with-libunwind = no
fno-unit-at-a-time = -fno-toplevel-reorder -fno-section-anchors
bind-now = no
have-hash-style = yes
use-default-link = no
output-format = elf32-i386

static-libgcc = -static-libgcc

versioning = yes
oldest-abi = default
exceptions = -fexceptions
multi-arch = default

mach-interface-list = 

have-bash2 = yes
have-ksh = yes

sizeof-long-double = 12

nss-crypt = no

# Configuration options.
build-static = yes
build-shared = yes
build-pic-default= no
build-profile = no
build-omitfp = no
build-bounded = no
build-static-nss = no
add-ons = libidn nptl ports
add-on-subdirs =  libidn
sysdeps-add-ons =  nptl ports
cross-compiling = no
force-install = yes

# Build tools.
CC = gcc
CXX = g++
BUILD_CC = 
CFLAGS = -g -O2
CPPFLAGS-config = 
ASFLAGS-config =  -Wa,--noexecstack
AR = ar
NM = nm
MAKEINFO = makeinfo
AS = $(CC) -c
MIG = 
PWD_P = /bin/pwd
BISON = no
AUTOCONF = autoconf
OBJDUMP = objdump
OBJCOPY = objcopy

# Installation tools.
INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_INFO = /usr/local/bin/install-info
LN_S = ln -s
MSGFMT = msgfmt

# Script execution tools.
BASH = /bin/bash
KSH = /bin/bash
AWK = gawk
PERL = /usr/bin/perl

# Additional libraries.
LIBGD = no

# Package versions and bug reporting configuration.
PKGVERSION = (EGLIBC) 
PKGVERSION_TEXI = (EGLIBC) 
REPORT_BUGS_TO = <http://www.eglibc.org/issues/>
REPORT_BUGS_TEXI = @uref{http://www.eglibc.org/issues/}

# More variables may be inserted below by configure.

override stddef.h = # The installed <stddef.h> seems to be libc-friendly.
