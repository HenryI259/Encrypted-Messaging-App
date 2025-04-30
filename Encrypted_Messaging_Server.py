import socket
import threading

# Creates socket
s = socket.socket()

# Port that information will be recieved in
port = 10000

# List of valid usernames
usernames = ["Alice", "Bob"]
max_username_length = 16

# Dictionary with pairs (name: client)
connected_users = {}

lock = threading.Lock()

# Encodes the sender and message together to be sent.
# The first half will be the username that is padded to be max_username_length
# The second half is the message itself
def bytes_to_message(sender, message):
    padding_length = max_username_length - len(sender)
    padding = bytes([0]*padding_length)
    padded_sender = sender.encode()+padding
    return padded_sender+message

# Function that will be run by a thread
# This handles all interactions with the client that connects
def handle_client(client, addr):
    try:
        print(f"User at address {addr} is attempting to connect to the server.")
        
        # Ensures the username is correct and not already connected
        username = "user"
        while username and not (username in usernames and username not in connected_users):
            username = client.recv(1024).decode().strip()
        
            with lock:
                if username not in usernames:
                    client.send(bytes_to_message("Server", "This username is not available.".encode()))
                    
                elif username in connected_users:
                    client.send(bytes_to_message("Server", "This user is already connected.".encode()))
    
        if not username:
            return
                    
        # Send success message to the client to inform them they have connected
        client.send(bytes_to_message("Server", "Success".encode()))
        connected_users[username] = client

        # Connect client with their peer and inform the peer
        print(f"{username} has connected to the server.")
        reciever = usernames[0] if username==usernames[1] else usernames[1]
        if reciever in connected_users:
            connected_users[reciever].send(bytes_to_message("Server", f"{username} has connected.".encode()))
        
        # Handles all messages sent by the client
        # Recieves their message and passes it to their peer if they are connected
        while True:
            message = client.recv(1024)
            if not message:
                break
            with lock:
                if reciever in connected_users:
                    connected_users[reciever].send(bytes_to_message(username, message))
                    print(f"{username} sent {reciever} a message")
                else:
                    client.send(bytes_to_message("Server", f"{reciever} is not connected at this time.".encode()))

    # Catches all exceptions and logs them
    except Exception as e:
        if username in locals():
            print(f"User {username} has experienced an error: {e}.")
        else:
            print(f"User at address {addr} has experienced an error: {e}.")
    # Ensures everything is closed properly
    finally:
        with lock:
            if "username" in locals() and username in connected_users:
                del connected_users[username]
                print(f"{username} has disconnected from the server.")
                if "reciever" in locals() and reciever in connected_users:
                    connected_users[reciever].send(bytes_to_message("Server", f"{username} has disconnected.".encode()))
            else:
                print(f"User at address {addr} has disconnected from the server.")
            client.close()


# Allows server to connect requests to this port
s.bind(("", port))
print(f"Socket binding to {port}")

# Listens for 2 connections
s.listen(2)
print("Listening for a connection from Alice or Bob")

# Accepts new clients and starts a new thread for each
while True:
    client, addr = s.accept()
    threading.Thread(target = handle_client, args=(client, addr)).start()
    
   
# cd source\repos\Encrypted-Messaging-App
# python Encrypted_Messaging_Server.py
# python Encrypted_Messaging_Client.py