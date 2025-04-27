import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

server = socket.socket()

port = 10000
server_addr = "127.0.0.1"

server.connect((server_addr, port))

connected = True

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
            sender, text = message.split(":", 1)
            message_area.config(state='normal')
            if sender == "Server":
                message_area.insert(tk.END, text, 'server')
            else:
                message_area.insert(tk.END, text, 'recieved')
            message_area.yview(tk.END)
            message_area.config(state="disabled")
        except Exception as e:
            print(f"Connection lost due to error: {e}")
            connected = False
            return
        
def send():
    global entry
    message = entry.get()
    if connected:
        server.send(message.encode())
        message_area.config(state='normal')
        message_area.insert(tk.END, message, 'sent')
        message_area.yview(tk.END)
        message_area.config(state="disabled")
    entry.delete(0, "end")


username = "Alice"#input("Please enter your username: ")
server.send(username.encode())

threading.Thread(target=recieve).start()

root = tk.Tk()

header = tk.Label(root, text="Encrypted Messaging App")
header.pack() 

message_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
message_area.tag_configure("recieved", justify="left")
message_area.tag_configure("sent", justify="right")
message_area.tag_configure("server", justify="center")
message_area.config(state="disabled")
message_area.pack()

entry = tk.Entry(root, width=50)
entry.pack()

send_button = tk.Button(root, text="Send", command=send)
send_button.pack()

root.mainloop()




