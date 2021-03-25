#!/usr/bin/env python3

##
# Simple HTTP Server to consume the INVITE message send by sipline executable
#   This script should be used for POC only
#   It only handels the INVITE type from incomming POST requests
##

import pathlib
import json
import vlc
from http.server import HTTPServer, BaseHTTPRequestHandler

# define interface for http server listener
NET = "0.0.0.0"
PORT = 2711

# define sound to play
SOUND = str(pathlib.Path().joinpath('sirenSound.mp3').absolute())

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        print("New POST request received, check if of type INVITE")
        contentLength = self.headers.get('Content-Length')
        if contentLength:
            bodyLength = int(contentLength)
            bodyPayload = self.rfile.read(bodyLength)
            
            try:
                print("DEBUG: Received body: {}".format(bodyPayload))
                bodyObject = json.loads(bodyPayload)
                print("DEBUG: Received parsed object: {}".format(bodyObject))
                if bodyObject and bodyObject['type'] == 0:
                    print("New POST request received, start playing a nice phone sound")
                    p = vlc.MediaPlayer("file://{}".format(SOUND))
                    p.play()
                    print("Done with playing sound, let's send some response and close http connection")
            except Exception as e:
                print("Failed to parse POST body payload")
                print(e)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello from server')        



print("Initiate HTTPServer for playing bell sound")
httpd = HTTPServer((NET, PORT), SimpleHTTPRequestHandler)
print("Start and run server forever")
httpd.serve_forever()
