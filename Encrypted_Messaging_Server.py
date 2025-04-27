import socket
import threading

# Server side functions
# Creates socket
s = socket.socket()

# Port that information will be recieved in
port = 10000

# List of valid usernames
usernames = ["Alice", "Bob"]

# Dictionary with pairs (name: client)
connected_users = {}

lock = threading.Lock()

def handle_client(client, addr):
    try:
        print(f"User at address {addr} is attempting to connect to the server.")
        
        username = "user"
        while username and not (username in usernames and username not in connected_users):
            username = client.recv(1024).decode().strip()
        
            with lock:
                if username not in usernames:
                    client.send("Server:This username is not available.".encode())
                    
                elif username in connected_users:
                    client.send("Server:This user is already connected.".encode())
            
        connected_users[username] = client

        print(f"{username} has connected to the server.")
        reciever = usernames[0] if username==usernames[1] else usernames[1]
        
        while True:
            message = client.recv(1024).decode()
            if not message:
                break
            with lock:
                if reciever in connected_users:
                    connected_users[reciever].send(f"{username}:{message}".encode())
                    print(f"{username} sent {reciever} a message")
                else:
                    client.send(f"Server:{reciever} is not connected at this time.".encode())

    except Exception as e:
        if username in locals():
            print(f"User {username} has experienced an error: {e}")
        else:
            print(f"User at address {addr} has experienced an error: {e}")
    finally:
        with lock:
            if "username" in locals() and username in connected_users:
                del connected_users[username]
                print(f"{username} has disconnected from the server.")
            else:
                print(f"User at address {addr} has disconnected from the server.")
            client.close()


# Allows server to connect requests to this port
s.bind(("", port))
print(f"Socket binding to {port}")

# Listens for 2 connections
s.listen(2)
print("Listening for a connection from Alice or Bob")

while True:
    client, addr = s.accept()
    threading.Thread(target = handle_client, args=(client, addr)).start()
    
   
# cd source\repos\Encrypted-Messaging-App
# python Encrypted_Messaging_Server.py
# python Encrypted_Messaging_Client.py