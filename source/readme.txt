This is the implementation of the protocol SVC++ for Linux. This version of SVC is high-performance but lack of reconnection control. It works well with the stable and high-speed network.
The two demos “file sending application” and "camera application" demonstrates the usage of SVC++ socket.

Building the solution:

  + Get prerequisites to build the protocol core:

    $ sudo apt-get install build-essential libgmp3-dev libssl-dev
  
  + The prerequisites for the camera demo (FFmpeg and SDL libraries):

    $ sudo apt-get install libavdevice-dev libavformat-dev libavfilter-dev libavcodec-dev libswscale-dev libavutil-dev libsdl2-dev

  + Build the demos (make sure the current directory is "source"):

    $ make all

The build process will generate inside 'bin' folder these binary files: fileserver.exe, fileclient.exe, camclient.exe, camserver.exe. The demos use SVC with SVCAuthenticatorSharedSecret as authentication mechanism, which requires a secret key stored inside 'bin/private/sharedsecret'. This folder/file must be placed along with client.exe file.

To run the "send file application":
  
  + run fileserver.exe in the server side:

  	$ ./fileserver.exe

  + run fileclient.exe in the client side:

    $ ./fileclient.exe <file_name> <server_address>

To run the "camera application":
	
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