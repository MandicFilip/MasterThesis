
import socket
import threading

# TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.bind(('0.0.0.0', 10000))
sock.listen(1)

response = "server 1 response"


def handler(c, a):
    while True:
        data = c.recv(1024)
        print(data)
        c.send(bytes(response))
        if not data:
            c.close()
            break


while True:
    c, a = sock.accept()
    cThread = threading.Thread(target=handler, args=(c, a))
    cThread.daemon = True
    cThread.start()
