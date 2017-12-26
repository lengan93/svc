BINDIR = ./bin
SRCDIR = ./src

CCOMPL = g++
CINCLU = -I./src/utils -I./src/crypto
CFLAGS = -std=c++11 -pthread -lrt -lgmp
CDEBUG = -O0 -g

FFMPEG = -lavdevice -lavfilter -lavformat -lavcodec -lswscale -lavresample -lavutil -lm -lSDL2
# ARMCOMPL = ~/rpi/x-tools/arm-unknown-linux-gnueabi/bin/arm-unknown-linux-gnueabi-c++
OPENSSL = -lcrypto -ldl

CRYPTO = $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/ECCurve.cpp 
AUTH = $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp
UTIL = $(SRCDIR)/svc/svc-utils.cpp

all: fileclient fileserver camclient camserver

local: daemon client camclient
full: daemon client server camclient camserver
camera: daemon camclient camserver
multinet: multinetclient multinetserver

daemon:
	$(CCOMPL) -static -o $(BINDIR)/daemon.exe $(SRCDIR)/svc/svc-daemon.cpp $(SRCDIR)/htp/HTP.cpp $(UTIL) $(CRYPTO) $(CFLAGS) $(CINCLU) $(CDEBUG)

library:	
	$(CCOMPL) -c $(UTIL) $(CRYPTO) $(CFLAGS) $(CINCLU) $(CDEBUG)
	mv *.o bin/
	ar rcs libsvc.a bin/*.o
	
camclient:	
	$(CCOMPL) -o $(BINDIR)/camclient.exe ./clientApp/FFmpegCameraApp.cpp $(UTIL) $(CRYPTO) $(AUTH) $(CFLAGS) $(OPENSSL) $(CINCLU) $(CDEBUG) $(FFMPEG)

camserver:
	$(CCOMPL) -o $(BINDIR)/camserver.exe ./serverApp/FFmpegCameraAppServer.cpp $(UTIL) $(CRYPTO) $(AUTH) $(CFLAGS) $(OPENSSL) $(CINCLU) $(CDEBUG) $(FFMPEG)

camclient2:	
	$(CCOMPL) -ggdb `pkg-config --cflags opencv` -o $(BINDIR)/camclient2.exe ./clientApp/OpenCVCameraApp.cpp `pkg-config --libs opencv` $(SRCDIR)/svc/SVC.cpp $(UTIL) $(CRYPTO) $(AUTH) $(CFLAGS) $(CINCLU) $(CDEBUG)

camserver2:
	$(CCOMPL) -ggdb `pkg-config --cflags opencv` -o $(BINDIR)/camserver2.exe ./serverApp/OpenCVCameraAppServer.cpp `pkg-config --libs opencv` $(SRCDIR)/svc/SVC.cpp $(UTIL) $(CRYPTO) $(AUTH) $(CFLAGS) $(CINCLU) $(CDEBUG)


clean		:
	rm -f $(BINDIR)/* $(SRCDIR)/svc/*.o $(SRCDIR)/utils/*.o $(SRCDIR)/crypto/*.o

armdaemon :
	$(ARMCOMPL) -static -o $(BINDIR)/daemon.exe $(SRCDIR)/svc/svc-daemon.cpp $(SRCDIR)/htp/HTP.cpp $(UTIL) $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/ECCurve.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)

armcamclient:	
	$(ARMCOMPL) -ggdb `pkg-config --cflags opencv` -o $(BINDIR)/camclient.exe ./clientApp/CameraApp.cpp `pkg-config --libs opencv` $(SRCDIR)/svc/SVC.cpp $(UTIL) $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(AUTH) $(CFLAGS) $(CINCLU) $(CDEBUG)

multinetclient:
	$(CCOMPL) -o $(BINDIR)/mnclient.exe ./multinet/SendFileApp.cpp ./multinet/multinet.cpp $(CFLAGS)

multinetserver:
	$(CCOMPL) -o $(BINDIR)/mnserver.exe ./multinet/SendFileAppServer.cpp ./multinet/multinet.cpp $(CFLAGS)

# client:	
# 	$(CCOMPL) -o $(BINDIR)/client.exe ./clientApp/SendFileApp.cpp $(SRCDIR)/svc/SVC.cpp $(UTIL) $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(AUTH) $(CFLAGS) $(CINCLU) $(CDEBUG)
# server:	
# 	$(CCOMPL) -static -o $(BINDIR)/server.exe ./serverApp/SendFileAppServer.cpp $(SRCDIR)/svc/SVC.cpp $(UTIL) $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(AUTH) $(CFLAGS) $(CINCLU) $(CDEBUG)

fileclient:	
	$(CCOMPL) -o $(BINDIR)/fileclient.exe ./clientApp/SendFileApp.cpp $(UTIL) $(CRYPTO) $(AUTH) $(CFLAGS) $(OPENSSL) $(CINCLU) $(CDEBUG)


fileserver:	
	$(CCOMPL) -o $(BINDIR)/fileserver.exe ./serverApp/SendFileAppServer.cpp $(UTIL) $(CRYPTO) $(AUTH) $(CFLAGS) $(OPENSSL) $(CINCLU) $(CDEBUG)
