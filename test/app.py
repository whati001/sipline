import vlc
from http.server import HTTPServer, BaseHTTPRequestHandler

# define interface for http server listener
NET = "0.0.0.0"
PORT = 2711

# define sound to play
SOUND = "/home/akarner/Downloads/Warning Siren-SoundBible.com-898272278.mp3"


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        print("New POST request received, start playing a nice phone sound")
        self.send_response(200)
        self.end_headers()
        p = vlc.MediaPlayer("file://{}".format(SOUND))
        p.play()
        print("Done with playing sound, let's send some response and close http connection")
        self.wfile.write(b'Hello, world!')


httpd = HTTPServer((NET, PORT), SimpleHTTPRequestHandler)
httpd.serve_forever()
