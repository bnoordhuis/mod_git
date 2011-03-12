##
##  Makefile -- Build procedure for sample git Apache module
##  Autogenerated via ``apxs -n git -g''.
##

builddir=.
top_srcdir=/home/bnoordhuis/opt/httpd
top_builddir=/home/bnoordhuis/opt/httpd
include /home/bnoordhuis/opt/httpd/build/special.mk

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional defines, includes and libraries
#DEFS=-Dmy_define=my_value
#INCLUDES=-Imy/include/dir
#LIBS=-Lmy/lib/dir -lmylib
INCLUDES=-I/home/bnoordhuis/src/libgit2/include
LDFLAGS=-L/home/bnoordhuis/src/libgit2/build/static -lgit2
EXTRA_LDFLAGS=$(LDFLAGS)

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_git.o mod_git.lo mod_git.slo mod_git.la 

#   simple test
test: reload
	lynx -mime_header http://localhost/git

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

