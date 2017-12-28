This is the implementation of the protocol SVC for Linux. This version of SVC is low-performance but it provides the persistent connection which allow maintaining the connection even if the address of client is changed. It works well with the unstable network where the client may change the network frequently.
The two demos “file sending application” and "camera application" demonstrates the usage of SVC socket.

Building the solution:

  + Get prerequisites to build the protocol core:

    $ sudo apt-get install build-essential libgmp3-dev
  
  + The prerequisites for the camera demo (FFmpeg and SDL libraries):

    $ sudo apt-get install libavdevice-dev libavformat-dev libavfilter-dev libavcodec-dev libswscale-dev libavutil-dev libsdl2-dev

  + Build the demos (make sure the current directory is "source"):

    $ make all

The build process will generate inside 'bin' folder these binary files: daemon.exe, fileserver.exe, fileclient.exe, camclient.exe, camserver.exe. The demos use SVC with SVCAuthenticatorSharedSecret as authentication mechanism, which requires a secret key stored inside 'bin/private/sharedsecret'. This folder/file must be placed along with client.exe file.

To run the "send file application":
  
  + run daemon.exe from both client and server (these daemon must be kept running during tests)
    $ ./daemon.exe --start

  + run fileserver.exe in the server side:

  	$ ./fileserver.exe <RETRY_TIME>

  + run fileclient.exe in the client side:

    $ ./fileclient.exe <file_name> <RETRY_TIME> <server_address>

where RETRY_TIME is a positive integer (value of 10-15 recommended)

To run the "camera application":
	
  + run daemon.exe from both client and server (these daemon must be kept running during tests)
    $ ./daemon.exe --start

  + run camserver.exe in the server side:

    $ ./camserver.exe

  + run camclient.exe in the client side:

    $ ./camclient.exe <server_address>

**Notice for Raspberry Pi:

To running the "camera application" in some models of Raspberry Pi, you might need to enable camera support and/or camera driver module.

  + Enable camera support using raspi-config:

    $ sudo raspi-config

    Use the cursor keys to move to the camera option, and select 'enable'.

  + Enable camera driver module:

    $ sudo modprobe bcm2835-v4l2