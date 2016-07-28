#!/usr/bin/env python
# Sets up a basic site that can allow two browsers to connect to each
# other via WebRTC DataChannels, sending connection events via WebSockets.


from flask import Flask, send_from_directory
from flask_sockets import Sockets
import json

app = Flask(__name__)
sockets = Sockets(app)

channels = {}

@sockets.route('/channel/<name>')
def channel_socket(ws, name):
    if name in channels:
        channels[name].append(ws)
    else:
        channels[name] = [ws]

    print "Got new websocket on channel", name

    ws.send(json.dumps({"type": "hello", "msg": "From the server"}))

    while not ws.closed:
        message = ws.receive()
        print "Got msg:", message

        if message is None:
            continue

        for other_ws in channels[name]:
            if ws is not other_ws:
                other_ws.send(message)

    channels[name].remove(ws)
    for other_ws in channels[name]:
        other_ws.send(json.dumps({"type": "client_disconnected", "msg": {}}))


@app.route('/static/<path:path>')
def send_static(path):
    return app.send_from_directory('static', path)


@app.route('/')
def serve_site():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    from gevent import pywsgi
    from geventwebsocket.handler import WebSocketHandler
    server = pywsgi.WSGIServer(('', 5000), app, handler_class=WebSocketHandler)
    server.serve_forever()
