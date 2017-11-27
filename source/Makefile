BINDIR = ./bin
SRCDIR = ./src
CCOMPL = g++
CINCLU = -I./src/utils -I./src/crypto
CFLAGS = -std=c++11 -pthread -lrt -lgmp
CDEBUG = -O0 -g
FFMPEG = -lavdevice -lavfilter -lavformat -lavcodec -lswscale -lavresample -lavutil -lm -lSDL2
ARMCOMPL = ~/rpi/x-tools/arm-unknown-linux-gnueabi/bin/arm-unknown-linux-gnueabi-c++

local: daemon client camclient
full: daemon client server camclient camserver
camera: daemon camclient camserver
multinet: multinetclient multinetserver

daemon:
	$(CCOMPL) -static -o $(BINDIR)/daemon.exe $(SRCDIR)/svc/svc-daemon.cpp $(SRCDIR)/htp/HTP.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/ECCurve.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
client:	
	$(CCOMPL) -o $(BINDIR)/client.exe ./clientApp/SendFileApp.cpp $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
server:	
	$(CCOMPL) -static -o $(BINDIR)/server.exe ./serverApp/SendFileAppServer.cpp $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
	
camclient:	
	$(CCOMPL) -ggdb `pkg-config --cflags opencv` -o $(BINDIR)/camclient.exe ./clientApp/CameraApp.cpp `pkg-config --libs opencv` $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)

camserver:
	$(CCOMPL) -ggdb `pkg-config --cflags opencv` -o $(BINDIR)/camserver.exe ./serverApp/CameraAppServer.cpp `pkg-config --libs opencv` $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)

camclient2:	
	$(CCOMPL) -o $(BINDIR)/camclient2.exe ./clientApp/FFmpegCameraApp.cpp $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG) $(FFMPEG)

camserver2:
	$(CCOMPL) -o $(BINDIR)/camserver2.exe ./serverApp/FFmpegCameraAppServer.cpp $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG) $(FFMPEG)

clean		:
	rm -f $(BINDIR)/* $(SRCDIR)/svc/*.o $(SRCDIR)/utils/*.o $(SRCDIR)/crypto/*.o

armdaemon :
	$(ARMCOMPL) -static -o $(BINDIR)/daemon.exe $(SRCDIR)/svc/svc-daemon.cpp $(SRCDIR)/htp/HTP.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/ECCurve.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)

armcamclient:	
	$(ARMCOMPL) -ggdb `pkg-config --cflags opencv` -o $(BINDIR)/camclient.exe ./clientApp/CameraApp.cpp `pkg-config --libs opencv` $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)

multinetclient:
	$(CCOMPL) -o $(BINDIR)/mnclient.exe ./multinet/SendFileApp.cpp ./multinet/multinet.cpp $(CFLAGS)

multinetserver:
	$(CCOMPL) -o $(BINDIR)/mnserver.exe ./multinet/SendFileAppServer.cpp ./multinet/multinet.cpp $(CFLAGS)

client2:	
	$(CCOMPL) -o $(BINDIR)/client2.exe ./clientApp/SendFileApp.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/ECCurve.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
server2:	
	$(CCOMPL) -static -o $(BINDIR)/server2.exe ./serverApp/SendFileAppServer.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
