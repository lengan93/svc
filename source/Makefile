BINDIR = ./bin
SRCDIR = ./src
CCOMPL = g++
CINCLU = -I./src/utils -I./src/crypto
CFLAGS = -pthread -std=c++11 -lrt
CDEBUG = -O0 -g

objs = daemon.o utils.o


daemon		:	$(objs)
	$(CCOMPL) -o $(BINDIR)/daemon.exe $(objs)

daemon.o	:	$(SRCDIR)/svc/SVC-daemon.cpp
	$(CCOMPL) -o daemon.o $(SRCDIR)/svc/SVC-daemon.cpp $(CINCLU) $(CFLAGS) $(CDEBUG)
	
utils.o		:	$(SRCDIR)/svc/SVC-utils.cpp
	$(CCOMPL) -o utils.o $(SRCDIR)/svc/SVC-utils.cpp $(CINCLU) $(CFLAGS) $(CDEBUG)
	
clean		:
	rm -f $(BINDIR)/* $(SRCDIR)/svc/*.o $(SRCDIR)/utils/*.o $(SRCDIR)/crypto/*.o
