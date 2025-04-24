import socket
import threading

# Server side functions
# Creates socket
s = socket.socket()

# Port that information will be recieved in
port = 10000

alice_client = None
alice_addr = None
send_to_alice_queue = ["3".encode(), "4".encode()]

bob_client = None
bob_addr = None
send_to_bob_queue = ["1".encode(), "2".encode()]

def handle_recv(client):
    disconnected = False
    try:
        data = client.recv(1024)
        if not data:
            disconnected = True
            client.close()
    except ConnectionResetError:
        disconnected = True
        client.close()
    except OSError:
        disconnected = True
        client.close()

    return data.decode(), disconnected

def recieve_from_alice():
    global alice_client
    if alice_client:
        message, disconnected = handle_recv(alice_client)
        if disconnected:
            alice_client = None;
        else:
            send_to_bob_queue.append(message.encode())

def recieve_from_bob():
    global bob_client
    if bob_client:
        message, disconnected = handle_recv(bob_client)
        if disconnected:
            bob_client = None;
        else:
            send_to_alice_queue.append(message.encode())

# Allows server to connect requests to this port
s.bind(("", port))
print(f"Socket binding to {port}")

# Listens for 2 connections
s.listen(2)
print("Listening for a connection from Alice or Bob")

#bob_thread = threading.Thread(target=recieve_from_bob)
#alice_thread = threading.Thread(target=recieve_from_alice)

#bob_thread.start()
#alice_thread.start()


while True:
    while not bob_client or not alice_client:
        client, addr = s.accept()
        client.send("Hello! What is your name?\n".encode())
        name, disconnected = handle_recv(client)
        if disconnected:
            print("Client disconnected")
        if name != "Bob" and name !=  "Alice":
            client.send("You are not the correct user. Goodbye.\n".encode())
            client.close()
        elif name == "Bob" and bob_client:
            client.send("Bob is already connected. Goodbye.\n".encode())
            client.close()
        elif name == "Alice" and alice_client:
            client.send("Alice is already connected. Goodbye.\n".encode())
            client.close()
        elif name == "Bob":
            if alice_client:
                client.send("Hello Bob! You are now connected to Alice.\n".encode())
            else:
                client.send("Hello Bob! Waiting for Alice.\n".encode())
            bob_client = client
            bob_addr = addr
        elif name == "Alice":
            if bob_client:
                client.send("Hello Alice! You are now connected to Bob.\n".encode())
            else:
                client.send("Hello Alice! Waiting for Bob.\n".encode())
            alice_client = client
            alice_addr = addr

    while(len(send_to_alice_queue) > 0): alice_client.send(send_to_alice_queue.pop(0))
    while(len(send_to_bob_queue) > 0): bob_client.send(send_to_bob_queue.pop(0))

    if not alice_client: bob_client.send("Alice has disconnected\n".encode())
    if not bob_client: alice_client.send("Bob has disconnected\n".encode())

bob_client.close()
alice_client.close()
print("Closed connections")
   
# cd source\repos\Encrypted-Messaging-App
# python Encrypted_Messaging_Server.py
# python Encrypted_Messaging_Client.py