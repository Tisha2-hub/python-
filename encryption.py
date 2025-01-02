import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Global dictionary to hold user data
users = {}

# Function to derive a key from password and salt
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to register a new user
def register_user(username, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    users[username] = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'key': base64.b64encode(key).decode('utf-8')
    }
    return key

# Function to log in an existing user
def login_user(username, password):
    if username not in users:
        messagebox.showerror("Error", "User not found")
        return None
    
    user_data = users.get(username)
    if 'salt' not in user_data or 'key' not in user_data:
        messagebox.showerror("Error", "User data corrupted or incomplete")
        return None

    salt = base64.b64decode(user_data['salt'])
    stored_key = base64.b64decode(user_data['key'])
    derived_key = derive_key(password, salt)

    if derived_key == stored_key:
        return derived_key
    else:
        messagebox.showerror("Error", "Incorrect password")
        return None

class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Encryption Suite")
        self.geometry("500x600")
        self.configure(bg="#34495e")  # Dark blue-gray background
        self.current_user = None
        self.key = None

        self.load_users()
        self.create_widgets()

    def load_users(self):
        if os.path.exists("users.json"):
            with open("users.json", "r") as f:
                global users
                users = json.load(f)

    def save_users(self):
        with open("users.json", "w") as f:
            json.dump(users, f)

    def create_widgets(self):
        self.login_frame = ttk.Frame(self, padding="20", style="LoginFrame.TFrame")
        self.login_frame.pack(expand=True, fill="both")

        ttk.Label(self.login_frame, text="Username:", background="#34495e", foreground="white").pack(pady=(20, 5))
        self.username_entry = ttk.Entry(self.login_frame, foreground="black", background="#34495e")
        self.username_entry.pack(pady=(0, 10))

        ttk.Label(self.login_frame, text="Password:", background="#34495e", foreground="white").pack(pady=(0, 5))
        self.password_entry = ttk.Entry(self.login_frame, show='*', foreground="black", background="#34495e")
        self.password_entry.pack(pady=(0, 10))

        ttk.Button(self.login_frame, text="Login", command=self.login, style="LoginButton.TButton").pack(pady=(10, 5))
        ttk.Button(self.login_frame, text="Register", command=self.register, style="RegisterButton.TButton").pack(pady=(5, 20))

        # Main menu frame
        self.style = ttk.Style(self)
        self.style.configure("MenuFrame.TFrame", background="#34495e")
        self.main_menu_frame = ttk.Frame(self, padding="20", style="MenuFrame.TFrame")
        
        # Main menu buttons
        ttk.Button(self.main_menu_frame, text="Encrypt Text", command=self.encrypt_text_window, style="MenuButton.TButton").pack(pady=(10, 5))
        ttk.Button(self.main_menu_frame, text="Decrypt Text", command=self.decrypt_text_window, style="MenuButton.TButton").pack(pady=(10, 5))
        ttk.Button(self.main_menu_frame, text="Encrypt File", command=self.encrypt_file, style="MenuButton.TButton").pack(pady=(10, 5))
        ttk.Button(self.main_menu_frame, text="Decrypt File", command=self.decrypt_file, style="MenuButton.TButton").pack(pady=(10, 5))
        ttk.Button(self.main_menu_frame, text="Logout", command=self.logout, style="LogoutButton.TButton").pack(pady=(10, 5))

        # Custom styles
        self.style.configure("LoginFrame.TFrame", background="#34495e")
        self.style.configure("MenuButton.TButton", background="#2ecc71", foreground="black", padding=10)
        self.style.configure("LoginButton.TButton", background="black", foreground="black", padding=10)
        self.style.configure("RegisterButton.TButton", background="black", foreground="black", padding=10)
        self.style.configure("LogoutButton.TButton", background="#e74c3c", foreground="black", padding=10)

        for button_style in ["LoginButton.TButton", "RegisterButton.TButton", "MenuButton.TButton", "LogoutButton.TButton"]:
            self.style.map(button_style,
                           background=[('active', '#16a085'), ('pressed', '#1abc9c')],
                           foreground=[('active', 'black'), ('pressed', 'black')])

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        key = login_user(username, password)
        if key:
            self.current_user = username
            self.key = key
            messagebox.showinfo("Success", "Login successful!")
            
            self.login_frame.pack_forget()
            self.main_menu_frame.pack(expand=True, fill="both")
        else:
            messagebox.showerror("Error", "Login failed")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username in users:
            messagebox.showerror("Error", "Username already exists")
        else:
            self.key = register_user(username, password)
            self.current_user = username
            messagebox.showinfo("Success", "Registration successful!")
            self.save_users()
            self.login_frame.pack_forget()
            self.main_menu_frame.pack(expand=True, fill="both")

    def encrypt(self, data):
        f = Fernet(self.key)
        return f.encrypt(data.encode()).decode()

    def decrypt(self, data):
        f = Fernet(self.key)
        return f.decrypt(data.encode()).decode()

    def encrypt_text_window(self):
        encrypt_window = tk.Toplevel(self)
        encrypt_window.title("Encrypt Text")
        encrypt_window.geometry("400x300")
        encrypt_window.configure(bg="#34495e")

        ttk.Label(encrypt_window, text="Enter text to encrypt:", background="#34495e", foreground="white").pack(pady=(20, 5))
        text_entry = tk.Text(encrypt_window, height=5, width=40)
        text_entry.pack(pady=(0, 10))

        def encrypt_text():
            text = text_entry.get("1.0", tk.END).strip()
            if text:
                encrypted_text = self.encrypt(text)
                result_window = tk.Toplevel(encrypt_window)
                result_window.title("Encrypted Text")
                result_window.geometry("400x200")
                result_window.configure(bg="#34495e")
                ttk.Label(result_window, text="Encrypted Text:", background="#34495e", foreground="white").pack(pady=(20, 5))
                result_text = tk.Text(result_window, height=5, width=40)
                result_text.insert(tk.END, encrypted_text)
                result_text.config(state=tk.DISABLED)
                result_text.pack(pady=(0, 10))
            else:
                messagebox.showerror("Error", "Please enter text to encrypt")

        ttk.Button(encrypt_window, text="Encrypt", command=encrypt_text, style="MenuButton.TButton").pack(pady=10)

    def decrypt_text_window(self):
        decrypt_window = tk.Toplevel(self)
        decrypt_window.title("Decrypt Text")
        decrypt_window.geometry("400x300")
        decrypt_window.configure(bg="#34495e")

        ttk.Label(decrypt_window, text="Enter text to decrypt:", background="#34495e", foreground="white").pack(pady=(20, 5))
        text_entry = tk.Text(decrypt_window, height=5, width=40)
        text_entry.pack(pady=(0, 10))

        def decrypt_text():
            text = text_entry.get("1.0", tk.END).strip()
            if text:
                try:
                    decrypted_text = self.decrypt(text)
                    result_window = tk.Toplevel(decrypt_window)
                    result_window.title("Decrypted Text")
                    result_window.geometry("400x200")
                    result_window.configure(bg="#34495e")
                    ttk.Label(result_window, text="Decrypted Text:", background="#34495e", foreground="white").pack(pady=(20, 5))
                    result_text = tk.Text(result_window, height=5, width=40)
                    result_text.insert(tk.END, decrypted_text)
                    result_text.config(state=tk.DISABLED)
                    result_text.pack(pady=(0, 10))
                except Exception as e:
                    messagebox.showerror("Error", "Decryption failed: " + str(e))
            else:
                messagebox.showerror("Error", "Please enter text to decrypt")

        ttk.Button(decrypt_window, text="Decrypt", command=decrypt_text, style="MenuButton.TButton").pack(pady=10)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                f = Fernet(self.key)
                encrypted_data = f.encrypt(file_data)
                save_path = filedialog.asksaveasfilename(defaultextension=".enc")
                if save_path:
                    with open(save_path, 'wb') as file:
                        file.write(encrypted_data)
                    messagebox.showinfo("Success", "File encrypted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")


    def decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()

                f = Fernet(self.key)
                decrypted_data = f.decrypt(encrypted_data)

                save_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                        filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
                if save_path:
                    with open(save_path, 'wb') as file:
                        file.write(decrypted_data)
                    messagebox.showinfo("Success", "File decrypted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")


    def logout(self):
        self.current_user = None
        self.key = None
        self.main_menu_frame.pack_forget()
        self.login_frame.pack(expand=True, fill="both")

if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
