

Running the Demo
----------------

To run the demo, first run:

	cd examples
	python site-api.py

This should start a web server on localhost:5000

	Open http://localhost:5000
	Enter channel name "test"
	Click "connect" - This should show up in the python console

Then, run 

	build/examples/websocket_client/testclient - its important that this be started after the web browser has connected to the test channel.

You should then see a whole heap of ICE messages, followed by a "Hello from native code"
