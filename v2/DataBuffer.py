import queue
import threading

from Manager import Manager

MAX_QUEUE_SIZE = 1000

INITIALIZE_SERVER_MESSAGE_TYPE = 'INITIALIZE_SERVER'
UPDATE_MESSAGE_TYPE = 'UPDATE'


class ServerWorker(threading.Thread):
    def __init__(self, data_queue):
        super().__init__()
        self.data_queue = data_queue
        self.manager = Manager()

    def process_data(self, data):
        if 'message_type' in data:
            if data['message_type'] == INITIALIZE_SERVER_MESSAGE_TYPE:
                print('Picked work - Init')
                self.manager.initialize(data)
            if data['message_type'] == UPDATE_MESSAGE_TYPE:
                print('Picked work - Update')
                self.manager.on_update(data)
        else:
            print('Received message without message type: ' + str(data))

    def run(self):
        while True:
            data = self.data_queue.get()
            self.process_data(data)


class DataBuffer:
    def __init__(self):
        self.data_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.worker = ServerWorker(self.data_queue)
        self.worker.start()

    def put(self, data):
        self.data_queue.put(item=data)
