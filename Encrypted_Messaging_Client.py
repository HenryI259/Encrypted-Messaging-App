import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import hashlib

server = socket.socket()

port = 10000
server_addr = "10.205.227.129"

server.connect((server_addr, port))

connected = True
state = "login"
key = ""

def get_hashed_key():
    global key
    modified_key = f"{key}:{int(time.time() / 1000)}"
    encoded_data = modified_key.encode()
    return hashlib.sha256(encoded_data).digest()

def encrypt(message):
    hashed_key = get_hashed_key()
    iv = get_random_bytes(AES.block_size)

    cipher_object = AES.new(hashed_key, AES.MODE_CBC, iv)

    padding_length = AES.block_size - len(message)%AES.block_size
    padding = bytes([padding_length]*padding_length)
    padded_message = message.encode()+padding

    return iv + cipher_object.encrypt(padded_message)

def decrypt(IVciphertext):
    hashed_key = get_hashed_key()
    iv = IVciphertext[:16]
    ciphertext = IVciphertext[16:]

    cipher_object = AES.new(hashed_key, AES.MODE_CBC, iv)
    plaintext = cipher_object.decrypt(ciphertext)
    
    return plaintext[:-plaintext[-1]].decode()

def recieve():
    global connected
    global state
    while True:
        try:
            message = server.recv(1024)
            if not message:
                print(f"Connection has been lost.")
                connected = False
                return
            sender = message[:16].rstrip(b'\x00').decode()
            text = message[16:]
            if state == "login":
                text = text.decode()
                if text == "Success":
                    state = "chat"
                    chat_frame.show_frame()
                else:
                    login_frame.entry.delete(0, "end")
                    login_frame.text_box.delete("1.0", "end")
                    login_frame.text_box.insert("1.0", "Please enter your username.\n")
                    login_frame.text_box.insert("end", text)
            elif state == "chat":
                chat_frame.message_area.config(state="normal")
                chat_frame.decrypted_message_area.config(state="normal")
                if sender == "Server":
                    text = text.decode()
                    chat_frame.decrypted_message_area.insert(tk.END, text+"\n", "server")
                else:
                    chat_frame.message_area.insert(tk.END, text.hex()+"\n", "recieved")
                    text = decrypt(text)
                    if text == "":
                        chat_frame.decrypted_message_area.insert(tk.END, "Your keys do not match.\n", "server")
                    else:
                        chat_frame.decrypted_message_area.insert(tk.END, text+"\n", "recieved")
                chat_frame.message_area.yview(tk.END)
                chat_frame.message_area.config(state="disabled")
                chat_frame.decrypted_message_area.yview(tk.END)
                chat_frame.decrypted_message_area.config(state="disabled")
        except Exception as e:
            print(f"Connection lost due to error: {e}")
            connected = False
            return
        
def send_username(login_frame):
    data = login_frame.entry.get()
    if connected and data.strip() != "":
        server.send(data.encode())

def submit_key(chat_frame):
    global key
    data = chat_frame.key_entry.get()
    if data.strip() != "":
        key = data
        print(f"Key has been set to: {key}")
        chat_frame.key_entry.delete(0, "end")

def send_chat(chat_frame):
    message = chat_frame.entry.get()
    if connected and message.strip() != "":
        if key == "":
            chat_frame.message_area.config(state="normal")
            chat_frame.message_area.insert(tk.END, "Please input a key.\n", "server")
            chat_frame.message_area.yview(tk.END)
            chat_frame.message_area.config(state="disabled")
        else:
            encrypted_message = encrypt(message)
            server.send(encrypted_message)
            chat_frame.message_area.config(state="normal")
            chat_frame.message_area.insert(tk.END, encrypted_message.hex()+"\n", "sent")
            chat_frame.message_area.yview(tk.END)
            chat_frame.message_area.config(state="disabled")
            chat_frame.decrypted_message_area.config(state="normal")
            chat_frame.decrypted_message_area.insert(tk.END, message+"\n", "sent")
            chat_frame.decrypted_message_area.yview(tk.END)
            chat_frame.decrypted_message_area.config(state="disabled")
    chat_frame.entry.delete(0, "end")

class AppFrame(tk.Frame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def show_frame(self):
        self.lift()
        
class LoginFrame(AppFrame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.text_box = tk.Text(self, width=50, height=2)
        self.text_box.insert("1.0", "Please enter your username.\n")
        self.text_box.pack()
        
        self.entry = tk.Entry(self, width=50)
        self.entry.pack()

        self.submit_button = tk.Button(self, text="Submit", command= lambda : send_username(self))
        self.submit_button.pack()

        
class ChatFrame(AppFrame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key_entry = tk.Entry(self, width=50)
        self.key_entry.grid(row=0)

        self.key_submit = tk.Button(self, text="Submit", command=lambda : submit_key(self))
        self.key_submit.grid(row=0, column=1)
        
        self.message_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=60)
        self.message_area.tag_configure("recieved", justify="left")
        self.message_area.tag_configure("sent", justify="right")
        self.message_area.tag_configure("server", justify="center")
        self.message_area.config(state="disabled")
        self.message_area.grid(row=1, column=0)

        self.decrypted_message_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=60)
        self.decrypted_message_area.tag_configure("recieved", justify="left")
        self.decrypted_message_area.tag_configure("sent", justify="right")
        self.decrypted_message_area.tag_configure("server", justify="center")
        self.decrypted_message_area.config(state="disabled")
        self.decrypted_message_area.grid(row=1, column=1)

        self.entry = tk.Entry(self, width=50)
        self.entry.grid(row=2, column=0)

        self.send_button = tk.Button(self, text="Send", command= lambda: send_chat(self))
        self.send_button.grid(row=2, column=1)
    

#username = "Bob"#input("Please enter your username: ")
#server.send(username.encode())

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




