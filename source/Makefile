BINDIR = ./bin
SRCDIR = ./src
CCOMPL = g++
CINCLU = -I./src/utils -I./src/crypto
CFLAGS = -std=c++11 -pthread -lrt -lgmp
CDEBUG = -O0 -g
FFMPEG = -lavdevice -lavfilter -lavformat -lavcodec -lswscale -lavresample -lavutil -lm -lSDL2
ARMCOMPL = ~/rpi/x-tools/arm-unknown-linux-gnueabi/bin/arm-unknown-linux-gnueabi-c++
OPENSSL = -lcrypto -ldl

local: daemon client camclient
full: daemon client server camclient camserver
camera: daemon camclient camserver
multinet: multinetclient multinetserver

daemon:
	$(CCOMPL) -static -o $(BINDIR)/daemon.exe $(SRCDIR)/svc/svc-daemon.cpp $(SRCDIR)/htp/HTP.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/ECCurve.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
	
camclient:	
	$(CCOMPL) -o $(BINDIR)/camclient.exe ./clientApp/FFmpegCameraApp.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/ECCurve.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(OPENSSL) $(CINCLU) $(CDEBUG) $(FFMPEG)

camserver:
	$(CCOMPL) -o $(BINDIR)/camserver.exe ./serverApp/FFmpegCameraAppServer.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/ECCurve.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(OPENSSL) $(CINCLU) $(CDEBUG) $(FFMPEG)

camclient2:	
	$(CCOMPL) -ggdb `pkg-config --cflags opencv` -o $(BINDIR)/camclient2.exe ./clientApp/OpenCVCameraApp.cpp `pkg-config --libs opencv` $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)

camserver2:
	$(CCOMPL) -ggdb `pkg-config --cflags opencv` -o $(BINDIR)/camserver2.exe ./serverApp/OpenCVCameraAppServer.cpp `pkg-config --libs opencv` $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)


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

# client:	
# 	$(CCOMPL) -o $(BINDIR)/client.exe ./clientApp/SendFileApp.cpp $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)
# server:	
# 	$(CCOMPL) -static -o $(BINDIR)/server.exe ./serverApp/SendFileAppServer.cpp $(SRCDIR)/svc/SVC.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(CINCLU) $(CDEBUG)

client:	
	$(CCOMPL) -o $(BINDIR)/client2.exe ./clientApp/SendFileApp.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/ECCurve.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(OPENSSL) $(CINCLU) $(CDEBUG)


server:	
	$(CCOMPL) -o $(BINDIR)/server2.exe ./serverApp/SendFileAppServer.cpp $(SRCDIR)/svc/svc-utils.cpp $(SRCDIR)/crypto/SHA256.cpp $(SRCDIR)/crypto/crypto-utils.cpp $(SRCDIR)/crypto/AESGCM.cpp $(SRCDIR)/crypto/AES256.cpp $(SRCDIR)/crypto/ECPoint.cpp $(SRCDIR)/crypto/ECCurve.cpp $(SRCDIR)/svc/authenticator/SVCAuthenticatorSharedSecret.cpp $(CFLAGS) $(OPENSSL) $(CINCLU) $(CDEBUG)
