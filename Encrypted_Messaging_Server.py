import socket

# Server side functions
# Creates socket
s = socket.socket()

# Port that information will be recieved in
port = 10000

# Allows server to connect requests to this port
s.bind(("", port))
print(f"Socket binding to {port}")

# Listens for 2 connections
s.listen(2)
print("Listening for a connection from Alice or Bob")

client1, addr1 = s.accept()
print(f"Connected to {addr1}")
client1.send("Hello! Waiting for second client.\n".encode())

client2, addr2 = s.accept()
print(f"Connected to {addr2}")
client2.send("Hello! You are now connected to the other client.\n".encode())
client1.send("The second client has now connected.\n".encode())

# Send a message to the client
client1.close()
client2.close()
print("Closed connections")
   
# cd source\repos\Encrypted-Messaging-App
# python Encrypted_Messaging_Server.py
# python Encrypted_Messaging_Client.py