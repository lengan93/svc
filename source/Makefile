BINDIR = ./bin
SRCDIR = ./src
CCOMPL = g++
CINCLU = -I./src/utils -I./src/crypto
CFLAGS = -pthread -std=c++11 -lrt
CDEBUG = -O0 -g


full:
	$(CCOMPL) -o $(BINDIR)/daemon.exe $(SRCDIR)/svc/SVC-daemon.cpp $(SRCDIR)/svc/SVC-utils.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
	
clean		:
	rm -f $(BINDIR)/* $(SRCDIR)/svc/*.o $(SRCDIR)/utils/*.o $(SRCDIR)/crypto/*.o
