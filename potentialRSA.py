import time
import random
import string
import math
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import os
import logging
from tkinter import messagebox

# Initialize the Tkinter application
root = tk.Tk()
root.title("RSA Encryption/Decryption")
root.geometry("400x500")

# Create a logging file
logging.basicConfig(filename='app_log.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Initialize the cryptography library
backend = default_backend()

def generate_key_pair():
    # Function to generate an RSA key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=backend
    )
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_pem, public_key_pem

def save_key_to_file(key_data, file_name):
    # Function to save a key to a file
    with open(file_name, 'wb') as f:
        f.write(key_data)

def load_key_from_file(file_name):
    # Function to load a key from a file
    with open(file_name, 'rb') as f:
        return f.read()

def encrypt_msg_with_key(msg, key_data):
    # Function to encrypt a message with a key
    try:
        key = serialization.load_pem_public_key(key_data, backend)
        encrypted = key.encrypt(
            msg.encode('utf-8'),
            padding.PKCS1v15()
        )
        return encrypted
    except Exception as e:
        logging.error(f'Encryption failed: {e}')
        messagebox.showerror("Encryption Error", "Encryption failed. Please check your key.")

def decrypt_msg_with_key(encrypted_msg, key_data):
    # Function to decrypt a message with a key
    try:
        key = serialization.load_pem_private_key(key_data, password=None, backend=backend)
        decrypted = key.decrypt(
            encrypted_msg,
            padding.PKCS1v15()
        )
        return decrypted
    except Exception as e:
        logging.error(f'Decryption failed: {e}')
        messagebox.showerror("Decryption Error", "Decryption failed. Please check your key.")

def load_private_key():
    # Function to load a private key from a file
    file_name = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if file_name:
        try:
            private_key = load_key_from_file(file_name)
            return private_key
        except Exception as e:
            logging.error(f'Private key loading failed: {e}')
            messagebox.showerror("Key Loading Error", "Failed to load the private key.")

def load_public_key():
    # Function to load a public key from a file
    file_name = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if file_name:
        try:
            public_key = load_key_from_file(file_name)
            return public_key
        except Exception as e:
            logging.error(f'Public key loading failed: {e}')
            messagebox.showerror("Key Loading Error", "Failed to load the public key.")

def generate_new_key_pair():
    # Function to generate a new key pair
    private_key, public_key = generate_key_pair()
    save_private_key_button = tk.Button(root, text="Save Private Key", command=lambda: save_key_to_file(private_key, "private_key.pem"))
    save_public_key_button = tk.Button(root, text="Save Public Key", command=lambda: save_key_to_file(public_key, "public_key.pem"))
    save_private_key_button.pack()
    save_public_key_button.pack()

def encrypt_message():
    # Function to encrypt a message with a selected public key
    msg = plaintext_entry.get()
    public_key = load_public_key()
    if public_key:
        encrypted_msg = encrypt_msg_with_key(msg, public_key)
        if encrypted_msg:
            encrypted_msg_text.delete('1.0', tk.END)
            encrypted_msg_text.insert(tk.END, encrypted_msg.hex())
            logging.info('Encryption successful.')
    else:
        result_label.config(text="Original Message: \nEncrypted Message: ")
        logging.error('Encryption failed.')

def decrypt_message():
    # Function to decrypt a message with a selected private key
    hex_encrypted_msg = encrypted_msg_text.get('1.0', tk.END)
    private_key = load_private_key()
    if private_key:
        encrypted_msg = bytes.fromhex(hex_encrypted_msg)
        decrypted_msg = decrypt_msg_with_key(encrypted_msg, private_key)
        if decrypted_msg:
            result_label.config(text=f"Decrypted Message: {decrypted_msg.decode('utf-8')}")
            logging.info('Decryption successful.')
        else:
            result_label.config(text="Original Message: \nDecrypted Message: ")
            logging.error('Decryption failed.')

# Create and place labels and input fields
p_label = tk.Label(root, text="RSA Encryption/Decryption")
p_label.config(font=("Arial", 16))
p_label.pack()

generate_new_key_button = tk.Button(root, text="Generate New Key Pair", command=generate_new_key_pair)
generate_new_key_button.config(font=("Arial", 12))
generate_new_key_button.pack()

load_private_key_button = tk.Button(root, text="Load Private Key", command=load_private_key)
load_private_key_button.config(font=("Arial", 12))
load_private_key_button.pack()

load_public_key_button = tk.Button(root, text="Load Public Key", command=load_public_key)
load_public_key_button.config(font=("Arial", 12))
load_public_key_button.pack()

plaintext_label = tk.Label(root, text="Enter the plain text message:", bg="black", fg='white')
plaintext_label.config(font=("Arial", 12))
plaintext_label.pack()
plaintext_entry = tk.Entry(root, width=40, font=("Arial", 12))
plaintext_entry.pack()

encrypted_msg_label = tk.Label(root, text="Encrypted Message:", bg="black", fg='white')
encrypted_msg_label.config(font=("Arial", 12))
encrypted_msg_label.pack()

encrypted_msg_text = tk.Text(root, height=5, width=40, font=("Arial", 12))
encrypted_msg_text.pack()

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_message)
encrypt_button.config(font=("Arial", 12),fg= "red")
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_message)
decrypt_button.config(font=("Arial", 12),fg="red")
decrypt_button.pack()

result_label = tk.Label(root, text="", font=("Arial", 14))
result_label.pack()

root.configure(bg="black")


root.mainloop()