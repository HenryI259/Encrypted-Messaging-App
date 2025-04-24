import socket

# Client side for bob

s = socket.socket()

port = 10000
server_addr = "127.0.0.1"

s.connect((server_addr, port))

print(s.recv(1024).decode())

s.close()

