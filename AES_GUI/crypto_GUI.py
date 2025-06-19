# -*- coding: utf-8 -*-
"""
Created on Thu Jun 19 15:47:19 2025

@author: karakuzuibrahim
"""

import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import base64



def pad(text):
    pad_len = 16 - (len(text.encode('utf-8')) % 16)
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

def aes_encrypt(plain_text, key):
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
    plain_text = pad(plain_text)
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(plain_text.encode('utf-8'))
    return base64.b64encode(iv + encrypted).decode('utf-8')

def aes_decrypt(enc_text, key):
    key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
    raw = base64.b64decode(enc_text)
    iv = raw[:16]
    encrypted = raw[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted).decode('utf-8')
    return unpad(decrypted)

def sha256_hash(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def sha256_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        return hashlib.sha256(data).hexdigest()


def encrypt_text():
    data = input_text.get("1.0", tk.END).strip()
    key = key_entry.get()
    if not data or not key:
        messagebox.showwarning("Uyarı", "Metin ve anahtar boş olamaz.")
        return
    try:
        encrypted = aes_encrypt(data, key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted)
    except Exception as e:
        messagebox.showerror("Hata", f"Şifreleme hatası:\n{str(e)}")

def decrypt_text():
    data = input_text.get("1.0", tk.END).strip()
    key = key_entry.get()
    if not data or not key:
        messagebox.showwarning("Uyarı", "Şifreli metin ve anahtar boş olamaz.")
        return
    try:
        decrypted = aes_decrypt(data, key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted)
    except Exception as e:
        messagebox.showerror("Hata", f"Çözme hatası:\n{str(e)}")

def hash_input_text():
    data = input_text.get("1.0", tk.END).strip()
    if not data:
        messagebox.showwarning("Uyarı", "Girdi metni boş olamaz.")
        return
    hashed = sha256_hash(data)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, hashed)

def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Metin Dosyaları", "*.txt")])
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            input_text.delete("1.0", tk.END)
            input_text.insert(tk.END, content)

def hash_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        hashed = sha256_file(file_path)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, hashed)

def save_output():
    content = output_text.get("1.0", tk.END).strip()
    if not content:
        messagebox.showwarning("Uyarı", "Kaydedilecek içerik yok.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        messagebox.showinfo("Başarılı", f"Sonuç {file_path} dosyasına kaydedildi.")


root = tk.Tk()
root.title("AES + SHA256 Şifreleme Arayüzü")
root.geometry("680x600")

tk.Label(root, text="Girdi Metni / Dosya İçeriği").pack()
input_text = tk.Text(root, height=8, width=80)
input_text.pack(pady=5)

tk.Label(root, text="Anahtar (Parola)").pack()
key_entry = tk.Entry(root, show="*", width=40)
key_entry.pack(pady=5)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Şifrele", command=encrypt_text).grid(row=0, column=0, padx=6)
tk.Button(btn_frame, text="Çöz", command=decrypt_text).grid(row=0, column=1, padx=6)
tk.Button(btn_frame, text="SHA256 (Metin)", command=hash_input_text).grid(row=0, column=2, padx=6)

file_btn_frame = tk.Frame(root)
file_btn_frame.pack()

tk.Button(file_btn_frame, text="Dosya Yükle", command=load_file).grid(row=0, column=0, padx=6)
tk.Button(file_btn_frame, text="SHA256 (Dosya)", command=hash_file).grid(row=0, column=1, padx=6)
tk.Button(file_btn_frame, text="Sonucu Kaydet", command=save_output).grid(row=0, column=2, padx=6)

tk.Label(root, text="Sonuç").pack()
output_text = tk.Text(root, height=8, width=80)
output_text.pack(pady=5)

root.mainloop()
