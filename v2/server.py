import socketserver
from http import server
import simplejson
import json
from Manager import Manager


def on_init(data_manager, config):
    print('Init')
    data_manager.initialize(config)


def on_stats(data_manager, data):
    print('Stats')
    data_manager.on_update(data)


manager = Manager()


class DataServer(server.BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def log_request(self, code='-', size='-'):
        return

    def do_POST(self):
        global manager

        self._set_response()
        content_length = int(self.headers['Content-Length'])  # Get the size of data
        post_data = self.rfile.read(content_length)  # Get the data as a string
        data = json.loads(simplejson.loads(post_data))

        if self.path == '/update':
            on_stats(manager, data)

        if self.path == '/initialize':
            on_init(manager, data)


httpServer = socketserver.TCPServer(("", 8080), DataServer)
httpServer.serve_forever()
