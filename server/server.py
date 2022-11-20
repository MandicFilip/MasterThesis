import socketserver
from http import server
import simplejson
import json

from DataBuffer import DataBuffer

SERVER_ENDPOINT = '/flows'


dataBuffer = DataBuffer()


class DataServer(server.BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def log_request(self, code='-', size='-'):
        return

    def do_POST(self):
        global dataBuffer

        self._set_response()
        content_length = int(self.headers['Content-Length'])  # Get the size of data
        post_data = self.rfile.read(content_length)  # Get the data as a string
        data = json.loads(simplejson.loads(post_data))

        if self.path == SERVER_ENDPOINT:
            dataBuffer.put(data)


httpServer = socketserver.TCPServer(("", 8080), DataServer)
httpServer.serve_forever()
