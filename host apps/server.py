import socket
import threading

# TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# UDP/IP
# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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
    client, address = sock.accept()
    cThread = threading.Thread(target=handler, args=(client, address))
    cThread.daemon = True
    cThread.start()
