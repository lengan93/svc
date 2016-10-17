BINDIR = ./bin
SRCDIR = ./src
CCOMPL = g++
CINCLU = -I./src/utils -I./src/crypto
CFLAGS = -pthread -std=c++11 -lrt
CDEBUG = -O0 -g


full: daemon client server
daemon:
	$(CCOMPL) -o $(BINDIR)/daemon.exe $(SRCDIR)/svc/SVC-daemon.cpp $(SRCDIR)/svc/SVC-utils.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
client:	
	$(CCOMPL) -o $(BINDIR)/client.exe ./clientApp/SendFileApp.cpp $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/SVC-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
server:	
	$(CCOMPL) -o $(BINDIR)/server.exe ./serverApp/SendFileAppServer.cpp $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/SVC-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
	
clean		:
	rm -f $(BINDIR)/* $(SRCDIR)/svc/*.o $(SRCDIR)/utils/*.o $(SRCDIR)/crypto/*.o
