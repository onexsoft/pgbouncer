PACKAGE_NAME = pgbouncer
PACKAGE_TARNAME = pgbouncer
PACKAGE_VERSION = 1.5.5
PACKAGE_STRING = pgbouncer 1.5.5
PACKAGE_URL = 
PACKAGE_BUGREPORT = 
PORTNAME = unix
EXEEXT = 
HAVE_CC_DEPFLAG = no
CC = gcc -std=gnu99
CPP = gcc -std=gnu99 -E
CPPFLAGS =  -I/usr/local/libevent/include
CFLAGS = -O2
DEFS = -DHAVE_CONFIG_H
WFLAGS =  -Wextra -Wno-missing-field-initializers -Wmissing-prototypes -Wpointer-arith -Wendif-labels -Wdeclaration-after-statement -Wold-style-definition -Wstrict-prototypes -Wundef -Wformat=2 -Wuninitialized
CXX = @CXX@
CXXFLAGS = @CXXFLAGS@
LD = @LD@
LDFLAGS = -g  -L/usr/local/libevent/lib
LIBS = -levent -lrt -lcrypt 
AR = ar
ARFLAGS = rcu
RANLIB = ranlib
LIBTOOL = @LIBTOOL@
INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
MKDIR_P = /bin/mkdir -p
SED = /bin/sed
AWK = gawk
GREP = /bin/grep
EGREP = /bin/grep -E
STRIP = strip
prefix = /usr/local/pgbouncer
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
includedir = ${prefix}/include
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datarootdir = ${prefix}/share
datadir = ${datarootdir}
sysconfdir = ${prefix}/etc
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
mandir = ${datarootdir}/man
libdir = ${exec_prefix}/lib
localedir = ${datarootdir}/locale
pkgdatadir = ${datarootdir}/pgbouncer
pkgconfigdir = ${libdir}/pkgconfig
abs_top_srcdir ?= /home/huih/work/code/pgbouncer
abs_top_builddir ?= /home/huih/work/code/pgbouncer
nosub_top_srcdir ?= .
nosub_top_builddir ?= .




XMLTO = 
ASCIIDOC = 
DLLWRAP = 
DLLTOOL = 
WINDRES = 

enable_debug = yes
have_libevent = yes
