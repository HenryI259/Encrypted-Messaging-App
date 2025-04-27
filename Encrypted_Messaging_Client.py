import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

server = socket.socket()

port = 10000
server_addr = "127.0.0.1"

server.connect((server_addr, port))

connected = True
state = "login"

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
            if state == "login":
                if text == "Success":
                    state = "chat"
                    chat_frame.show_frame()
                else:
                    login_frame.entry.delete(0, "end")
                    login_frame.text_box.delete("28.0", "end")
                    login_frame.text_box.insert("end", text)
            elif state == "chat":
                chat_frame.message_area.config(state="normal")
                if sender == "Server":
                    chat_frame.message_area.insert(tk.END, text+"\n", "server")
                else:
                    chat_frame.message_area.insert(tk.END, text+"\n", "recieved")
                chat_frame.message_area.yview(tk.END)
                chat_frame.message_area.config(state="disabled")
        except Exception as e:
            print(f"Connection lost due to error: {e}")
            connected = False
            return
        
def send_username():
    message = login_frame.entry.get()
    if connected and message.strip() != "":
        server.send(message.encode())

def send_chat():
    message = chat_frame.entry.get()
    if connected and message.strip() != "":
        server.send(message.encode())
        chat_frame.message_area.config(state="normal")
        chat_frame.message_area.insert(tk.END, message+"\n", "sent")
        chat_frame.message_area.yview(tk.END)
        chat_frame.message_area.config(state="disabled")
    chat_frame.entry.delete(0, "end")

class AppFrame(tk.Frame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def show_frame(self):
        self.lift()
        
class LoginFrame(AppFrame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.text_box = tk.Text(self, width=30, height=5)
        self.text_box.insert("1.0", "Please enter your username.\n")
        
        self.entry = tk.Entry(self, width=50)
        self.entry.pack()

        self.submit_button = tk.Button(self, text="Submit", command=send_username())
        self.submit_button.pack()

        
class ChatFrame(AppFrame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.message_area = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.message_area.tag_configure("recieved", justify="left")
        self.message_area.tag_configure("sent", justify="right")
        self.message_area.tag_configure("server", justify="center")
        self.message_area.config(state="disabled")
        self.message_area.pack()

        self.entry = tk.Entry(self, width=50)
        self.entry.pack()

        self.send_button = tk.Button(self, text="Send", command=send_chat)
        self.send_button.pack()
    

username = "Bob"#input("Please enter your username: ")
server.send(username.encode())

threading.Thread(target=recieve).start()

root = tk.Tk()
root.geometry("800x600")

header = tk.Label(root, text="Encrypted Messaging App")
header.pack() 

main_container = tk.Frame(root)
main_container.pack(side="top", fill="both", expand=True)

login_frame = LoginFrame(root)
login_frame.place(in_=main_container, x=0, y=0, relwidth=1, relheight=1)

chat_frame = ChatFrame(root)
chat_frame.place(in_=main_container, x=0, y=0, relwidth=1, relheight=1)

login_frame.show_frame()

root.mainloop()




