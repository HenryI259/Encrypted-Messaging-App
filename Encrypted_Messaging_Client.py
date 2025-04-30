import os
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import threading
import tkinter as tk
from tkinter import END, scrolledtext
import hashlib
import tkinter.font as tkFont
import pickle

server = socket.socket()

port = 10000
server_addr = "10.205.227.129"

server.connect((server_addr, port))

username = ""
connected = True
state = "login"
key = ""

messages = []

def load_messages():
    global messages
    if os.path.exists(f"{username}'s-message-file.pkl"):
        with open(f"{username}'s-message-file.pkl", "rb") as file:
            messages = pickle.load(file)

def save_messages():
    with open(f"{username}'s-message-file.pkl", "wb") as file:
        pickle.dump(messages, file)

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

def decrypt_all(chat_frame, new_key):
    chat_frame.message_area.config(state="normal")
    chat_frame.message_area.delete("1.0", END)
    for message_tuple in messages:
        message = message_tuple[0]
        time_addition = message_tuple[1]
        message_tag = message_tuple[2]
        
        modified_key = f"{new_key}:{time_addition}"
        encoded_data = modified_key.encode()
        hashed_key = hashlib.sha256(encoded_data).digest()
        
        iv = message[:16]
        ciphertext = message[16:]
        cipher_object = AES.new(hashed_key, AES.MODE_CBC, iv)
        plaintext = cipher_object.decrypt(ciphertext)
        try:
            plaintext = plaintext[:-plaintext[-1]].decode()
            if plaintext == "":
                chat_frame.message_area.insert(tk.END, "Failed to decrypt.\n", message_tag+"-warning")
            else:
                chat_frame.message_area.insert(tk.END, plaintext+"\n", message_tag)
        except:
            chat_frame.message_area.insert(tk.END, "Failed to decrypt.\n", message_tag+"-warning")
    
    
    chat_frame.message_area.yview(tk.END)
    chat_frame.message_area.config(state="disabled")

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
                    load_messages()
                    if len(messages) > 0:
                        chat_frame.message_area.config(state="normal")
                        chat_frame.message_area.insert(tk.END, "Input key to load past messages.\n", "server")
                        chat_frame.message_area.config(state="disabled")
                    chat_frame.show_frame()
                else:
                    login_frame.entry.delete(0, "end")
                    login_frame.text_box.config(state="normal")
                    login_frame.text_box.delete("1.0", "end")
                    login_frame.text_box.insert("1.0", "Please enter your username.\n", "center")
                    login_frame.text_box.insert("end", text, "center-warning")
                    login_frame.text_box.config(state="disabled")
            elif state == "chat":
                chat_frame.ciphertext_area.config(state="normal")
                chat_frame.message_area.config(state="normal")
                if sender == "Server":
                    text = text.decode()
                    chat_frame.message_area.insert(tk.END, text+"\n", "server")
                else:
                    chat_frame.ciphertext_area.insert(tk.END, text.hex()+"\n", "recieved")
                    messages.append((text, int(time.time() / 1000), "recieved"))
                    text = decrypt(text)
                    if text == "":
                        chat_frame.message_area.insert(tk.END, "Failed to decrypt.\n", "recieved-warning")
                    else:
                        chat_frame.message_area.insert(tk.END, text+"\n", "recieved")
                chat_frame.ciphertext_area.yview(tk.END)
                chat_frame.ciphertext_area.config(state="disabled")
                chat_frame.message_area.yview(tk.END)
                chat_frame.message_area.config(state="disabled")
        except Exception as e:
            chat_frame.message_area.config(state="normal")
            chat_frame.message_area.insert(tk.END, "Connection to server has been lost.\n", "server-warning")
            chat_frame.message_area.yview(tk.END)
            chat_frame.message_area.config(state="disabled")
            chat_frame.send_button.configure(text="Reload", command=lambda: reload(chat_frame))
            print(f"Connection lost due to: {e}")
            server.close()
            connected = False
            return
        
def send_username(login_frame):
    global username
    data = login_frame.entry.get().strip()
    if connected and data != "":
        server.send(data.encode())
        username = data

def submit_key(chat_frame):
    global key
    data = chat_frame.key_entry.get().strip()
    if data != "" and data != key:
        key = data
        print(f"Key has been set to: {key}")
        decrypt_all(chat_frame, key)
    chat_frame.key_entry.delete(0, "end")

def send_chat(chat_frame):
    message = chat_frame.entry.get()
    if connected and message.strip() != "":
        if key == "":
            chat_frame.message_area.config(state="normal")
            chat_frame.message_area.insert(tk.END, "Please input a key.\n", "server-warning")
            chat_frame.message_area.yview(tk.END)
            chat_frame.message_area.config(state="disabled")
        else:
            encrypted_message = encrypt(message)
            server.send(encrypted_message)
            chat_frame.ciphertext_area.config(state="normal")
            chat_frame.ciphertext_area.insert(tk.END, encrypted_message.hex()+"\n", "sent")
            chat_frame.ciphertext_area.yview(tk.END)
            chat_frame.ciphertext_area.config(state="disabled")
            chat_frame.message_area.config(state="normal")
            chat_frame.message_area.insert(tk.END, message+"\n", "sent")
            chat_frame.message_area.yview(tk.END)
            chat_frame.message_area.config(state="disabled")
            messages.append((encrypted_message, int(time.time() / 1000), "sent"))
    chat_frame.entry.delete(0, "end")
    
def reload(chat_frame):
    global connected
    global server
    try:
        server = socket.socket()
        server.connect((server_addr, port))
        server.send(username.encode())
        if server.recv(1024)[16:].decode() == "Success":
            threading.Thread(target=recieve, daemon=True).start()
            chat_frame.message_area.config(state="normal")
            chat_frame.message_area.insert(tk.END, "Reconnected to server.\n", "server")
            chat_frame.message_area.yview(tk.END)
            chat_frame.message_area.config(state="disabled")
            chat_frame.send_button.configure(text="Send", command= lambda: send_chat(chat_frame))
            connected = True
        else:
            chat_frame.message_area.config(state="normal")
            chat_frame.message_area.insert(tk.END, "Reconnect failed.\n", "server-warning")
            chat_frame.message_area.yview(tk.END)
            chat_frame.message_area.config(state="disabled")
            server.close()
    except Exception as e:
        print(f"Failed to connect due to error: {e}")
        chat_frame.message_area.config(state="normal")
        chat_frame.message_area.insert(tk.END, "Reconnect failed.\n", "server-warning")
        chat_frame.message_area.yview(tk.END)
        chat_frame.message_area.config(state="disabled")
        server.close()

def close():
    if state == "chat":
        save_messages()
    server.close()
    root.destroy()

class AppFrame(tk.Frame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def show_frame(self):
        self.lift()
        
class LoginFrame(AppFrame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.text_box = tk.Text(self, width=35, height=2)
        self.text_box.tag_configure("center", justify="center")
        self.text_box.tag_configure("center-warning", justify="center", foreground="red")
        self.text_box.insert("1.0", "Please enter your username.\n", "center")
        self.text_box.config(state="disabled")
        self.text_box.configure(foreground=main_text_color, bg=text_background_color)
        self.text_box.pack(pady=(150, 0))
        
        self.entry_frame = tk.Frame(self)
        self.entry_frame.configure(bg=background_color)
        self.entry_frame.pack()

        self.entry = tk.Entry(self.entry_frame, width=20)
        self.entry.configure(foreground=main_text_color, bg=text_background_color)
        self.entry.pack(side = tk.LEFT)

        self.submit_button = tk.Button(self.entry_frame, text="Submit", command= lambda : send_username(self))
        self.submit_button.configure(foreground=main_text_color, bg=text_background_color)
        self.submit_button.pack()

        
class ChatFrame(AppFrame):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.key_frame = tk.Frame(self)
        self.key_frame.configure(bg=background_color)
        self.key_frame.pack()
        
        self.key_entry = tk.Entry(self.key_frame, width=30)
        self.key_entry.configure(foreground=main_text_color, bg=text_background_color)
        self.key_entry.pack(side = tk.LEFT)

        self.key_submit = tk.Button(self.key_frame, text="Submit", command=lambda : submit_key(self))
        self.key_submit.configure(foreground=main_text_color, bg=text_background_color)
        self.key_submit.pack()
        
        self.ciphertext_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=60, height = 2)
        self.ciphertext_area.tag_configure("recieved", justify="left")
        self.ciphertext_area.tag_configure("sent", justify="right")
        self.ciphertext_area.config(state="disabled")
        self.ciphertext_area.configure(foreground=main_text_color, bg=text_background_color)
        self.ciphertext_area.pack()

        self.message_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=60)
        self.message_area.tag_configure("recieved", justify="left")
        self.message_area.tag_configure("recieved-warning", justify="left", foreground="red")
        self.message_area.tag_configure("sent", justify="right")
        self.message_area.tag_configure("sent-warning", justify="right", foreground="red")
        self.message_area.tag_configure("server", justify="center")
        self.message_area.tag_configure("server-warning", justify="center", foreground="red")
        self.message_area.config(state="disabled")
        self.message_area.configure(foreground=main_text_color, bg=text_background_color)
        self.message_area.pack()

        self.entry_frame = tk.Frame(self)
        self.entry_frame.configure(bg=background_color)
        self.entry_frame.pack()

        self.entry = tk.Entry(self.entry_frame, width=50)
        self.entry.configure(foreground=main_text_color, bg=text_background_color)
        self.entry.pack(side = tk.LEFT)

        self.send_button = tk.Button(self.entry_frame, text="Send", command= lambda: send_chat(self))
        self.send_button.configure(foreground=main_text_color, bg=text_background_color)
        self.send_button.pack()

threading.Thread(target=recieve, daemon=True).start()

background_color = "#101010"
text_background_color = "#202020"
main_text_color = "#ffffff"

root = tk.Tk()
root.geometry("800x600")
root.configure(bg=background_color)
root.title("Encrypted Messaging App")
root.protocol("WM_DELETE_WINDOW", close)

big_font = tkFont.Font(family="Roboto", size=20)
header = tk.Label(root, text="Encrypted Messaging App")
header.configure(foreground=main_text_color, bg=background_color, font=big_font)
header.pack() 

main_container = tk.Frame(root)
main_container.configure(bg=background_color)
main_container.pack(side="top", fill="both", expand=True)

login_frame = LoginFrame(root)
login_frame.configure(bg=background_color)
login_frame.place(in_=main_container, x=0, y=0, relwidth=1, relheight=1)

chat_frame = ChatFrame(root)
chat_frame.configure(bg=background_color)
chat_frame.place(in_=main_container, x=0, y=0, relwidth=1, relheight=1)

login_frame.show_frame()

root.mainloop()