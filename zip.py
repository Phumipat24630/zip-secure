import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
import zlib
import os
import json
import zipfile

def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def encrypt(data, key):
    data = pad(data)
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(data)

def decrypt(data, key):
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data[AES.block_size:])
    return plaintext.rstrip(b"\0")

def compress(data):
    return zlib.compress(data)

def decompress(data):
    return zlib.decompress(data)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor/Decryptor")
        self.key = os.urandom(16)  # 16-byte key for AES

        # Load or initialize the encrypted file data
        self.encrypted_files = self.load_encrypted_files()

        # Set up the interface
        self.frame = tk.Frame(self.root)
        self.frame.pack(padx=20, pady=20)
        tk.Button(self.frame, text="Encrypt, Compress and Save File", command=self.encrypt_and_compress_file).pack(fill=tk.X)
        tk.Button(self.frame, text="Decompress, Decrypt and Open File", command=self.decompress_and_decrypt_file).pack(fill=tk.X)
        tk.Button(self.frame, text="Show Encrypted Files", command=self.show_encrypted_files).pack(fill=tk.X)
        tk.Button(self.frame, text="Delete Encrypted Files", command=self.delete_encrypted_files).pack(fill=tk.X)

    def load_encrypted_files(self):
        try:
            with open("encrypted_files.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_encrypted_files(self):
        with open("encrypted_files.json", "w") as f:
            json.dump(self.encrypted_files, f)

    def encrypt_and_compress_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        file_extension = os.path.splitext(file_path)[1]
        with open(file_path, 'rb') as file:
            data = file.read()
        compressed_data = compress(data)
        encrypted_data = encrypt(compressed_data, self.key)

        save_path = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("Zip files", "*.zip")])
        if save_path:
            with zipfile.ZipFile(save_path, 'w') as zip_file:
                zip_file.writestr(os.path.basename(file_path), encrypted_data)
            self.encrypted_files[save_path] = True
            self.save_encrypted_files()
            messagebox.showinfo("Success", "File was encrypted, compressed, and saved as a zip file.")

    def decompress_and_decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Zip files", "*.zip")])
        if not file_path:
            return

        if file_path not in self.encrypted_files:
            messagebox.showerror("Error", "The selected file was not encrypted by this program.")
            return

        with zipfile.ZipFile(file_path, 'r') as zip_file:
            encrypted_data = zip_file.read(zip_file.namelist()[0])

        try:
            compressed_data = decrypt(encrypted_data, self.key)
            data = decompress(compressed_data)
            save_path = filedialog.asksaveasfilename(defaultextension=os.path.splitext(zip_file.namelist()[0])[1])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(data)
            messagebox.showinfo("Success", "File was decompressed, decrypted, and saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt the file. Check the key or file integrity.")

    def show_encrypted_files(self):
        if not self.encrypted_files:
            messagebox.showinfo("No Encrypted Files", "There are no encrypted files.")
            return

        message = "Encrypted files:\n"
        for file_path in self.encrypted_files:
            message += f"- {file_path}\n"

        messagebox.showinfo("Encrypted Files", message)

    def delete_encrypted_files(self):
        if not self.encrypted_files:
            messagebox.showinfo("No Encrypted Files", "There are no encrypted files to delete.")
            return

        # Create a new window to display the list of encrypted files
        delete_window = tk.Toplevel(self.root)
        delete_window.title("Delete Encrypted Files")

        # Create a listbox to display the encrypted files
        listbox = tk.Listbox(delete_window, width=80)
        listbox.pack(padx=20, pady=20)

        # Populate the listbox with the encrypted files
        for file_path in self.encrypted_files:
            listbox.insert(tk.END, file_path)

        # Create a "Delete Selected" button
        delete_button = tk.Button(delete_window, text="Delete Selected", command=lambda: self.delete_selected_files(listbox))
        delete_button.pack(pady=10)

    def delete_selected_files(self, listbox):
        selected_files = listbox.curselection()
        if not selected_files:
            messagebox.showinfo("No Files Selected", "Please select one or more files to delete.")
            return

        for i in reversed(selected_files):
            file_path = listbox.get(i)
            del self.encrypted_files[file_path]
        self.save_encrypted_files()

        # Refresh the listbox
        listbox.delete(0, tk.END)
        for file_path in self.encrypted_files:
            listbox.insert(tk.END, file_path)

        messagebox.showinfo("Files Deleted", "Selected files have been deleted from the encryption history.")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()

