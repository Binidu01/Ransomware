import os
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor")
        self.root.geometry("400x250")

        # Generate encryption key (consider saving the key securely for real-world use)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

        # UI Elements
        Label(root, text="Folder Path:").pack(pady=5)
        self.folder_entry = Entry(root, width=50)
        self.folder_entry.pack(pady=5)
        Button(root, text="Browse", command=self.browse_folder).pack(pady=5)

        Button(root, text="Encrypt Files", command=self.encrypt_files).pack(pady=5)
        Button(root, text="Decrypt Files", command=self.decrypt_files).pack(pady=5)

        # Predefined password (for demonstration purposes)
        self.password = "binidu01"

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_entry.delete(0, "end")
            self.folder_entry.insert(0, folder)

    def encrypt_files(self):
        folder_path = self.folder_entry.get()
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Invalid folder path!")
            return

        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    file_data = f.read()
                encrypted_data = self.cipher.encrypt(file_data)
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)

        messagebox.showinfo("Success", "Files encrypted successfully!")

    def decrypt_files(self):
        folder_path = self.folder_entry.get()
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Invalid folder path!")
            return

        attempts = 0
        while attempts < 3:
            password = self.get_password()
            if password == self.password:
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, "rb") as f:
                            encrypted_data = f.read()
                        try:
                            decrypted_data = self.cipher.decrypt(encrypted_data)
                        except Exception as e:
                            messagebox.showerror("Error", f"Decryption failed: {e}")
                            return
                        with open(file_path, "wb") as f:
                            f.write(decrypted_data)
                messagebox.showinfo("Success", "Files decrypted successfully!")
                return
            else:
                attempts += 1
                if attempts < 3:
                    messagebox.showwarning("Warning", f"Wrong password! {3 - attempts} attempts left.")
                else:
                    messagebox.showerror("Error", "Wrong password! No more attempts left.")

    def get_password(self):
        return simpledialog.askstring("Password", "Enter password to decrypt:", show="*")


if __name__ == "__main__":
    root = Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
