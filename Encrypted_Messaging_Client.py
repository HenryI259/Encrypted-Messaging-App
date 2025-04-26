import socket
import threading


server = socket.socket()

port = 10000
server_addr = "10.205.156.161"

server.connect((server_addr, port))

connected = True

def send():
    while True:
        message = input()
        if connected:
            server.send(message.encode())
        else:
            return

def recieve():
    global connected
    while True:
        try:
            message = server.recv(1024).decode()
            if not message:
                print(f"Connection has been lost.")
                connected = False
                return
            print(f"{message}")
        except Exception as e:
            print(f"Connection lost due to error: {e}")
            connected = False
            return


username = input("Please enter your username: ")
server.send(username.encode())

threading.Thread(target=recieve).start()
threading.Thread(target=send).start()



