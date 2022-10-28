import socketserver
from http import server
import simplejson
import json


def on_new_flow(data):
    print('New packet info')
    print(data)


def on_tcp_flags(data):
    print('Tcp flags info')
    print(data)

def on_stats(data):
    print('Stats')
    print(data)

class DataServer(server.BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        self._set_response()
        content_length = int(self.headers['Content-Length'])  # Get the size of data
        post_data = self.rfile.read(content_length)  # Get the data as a string
        data = json.loads(simplejson.loads(post_data))

        if self.path == '/new_flow':
            on_new_flow(data)

        if self.path == '/tcp_flags':
            on_tcp_flags(data)

        if self.path == '/stats':
            on_stats(data)


httpServer = socketserver.TCPServer(("", 8080), DataServer)
httpServer.serve_forever()