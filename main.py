import tkinter as tk
from tkinter import messagebox, scrolledtext
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

def xor_encrypt(text, key):
    encrypted = ""
    for char, key_char in zip(text, key):
        encrypted += chr(ord(char) ^ ord(key_char))
    return encrypted

def custom_hash(data):
    hash_value = 0
    prime = 31 
    for char in data:
        hash_value = (hash_value * prime + ord(char)) % (2**32)
    return hash_value

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, merkle_root):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.merkle_root = merkle_root
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = str(self.index) + str(self.previous_hash) + str(self.timestamp) + str(self.transactions) + str(self.merkle_root)
        return custom_hash(block_data)

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, "0", "01/01/2023", [], "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

def user_exists(username):
    try:
        with open(f"{username}.txt", "r"):
            return True
    except FileNotFoundError:
        return False

class EnhancedUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Blockchain Wallet")
        self.root.geometry("500x600")
        self.blockchain = Blockchain()
        self.create_widgets()

    def create_widgets(self):
        login_frame = ttk.Frame(self.root)
        login_frame.pack(padx=20, pady=20, fill=BOTH, expand=True)

        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky=W, pady=5)
        self.username_entry = ttk.Entry(login_frame)
        self.username_entry.grid(row=0, column=1, pady=5, sticky=EW)

        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky=W, pady=5)
        self.password_entry = ttk.Entry(login_frame, show="*")
        self.password_entry.grid(row=1, column=1, pady=5, sticky=EW)

        ttk.Button(login_frame, text="Register", command=self.register_user).grid(row=2, column=0, pady=10, sticky=EW)
        ttk.Button(login_frame, text="Login", command=self.login_user).grid(row=2, column=1, pady=10, sticky=EW)

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if user_exists(username):
            messagebox.showerror("Error", "User already exists")
            return

        try:
            with open(f"{username}.txt", "w") as file:
                encrypted_password = xor_encrypt(password, "mysecretkey")
                file.write(f"{encrypted_password}\n0") 
            messagebox.showinfo("Success", "User registered successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {str(e)}")

    def login_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not user_exists(username):
            messagebox.showerror("Error", "User not found")
            return

        try:
            with open(f"{username}.txt", "r") as file:
                stored_password = file.readline().strip()
                encrypted_password = xor_encrypt(stored_password, "mysecretkey")

                if password == encrypted_password:
                    messagebox.showinfo("Success", "Login successful!")
                    self.open_user_window(username)
                else:
                    messagebox.showerror("Error", "Invalid password")
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")

    def open_user_window(self, username):
        user_window = ttk.Toplevel(self.root)
        user_window.title(f"Welcome, {username}")
        user_window.geometry("400x500")

        money_label_var = ttk.StringVar()

        def update_money_label():
            with open(f"{username}.txt", "r") as file:
                encrypted_password, money_count = file.read().splitlines()
                money_count = int(money_count)
                money_label_var.set(f"Money: ${money_count}")

        money_label = ttk.Label(user_window, textvariable=money_label_var)
        money_label.pack(pady=20)

        add_money_label = ttk.Label(user_window, text="Add money:")
        add_money_label.pack(pady=5)

        add_money_entry = ttk.Entry(user_window)
        add_money_entry.pack(pady=5)

        def add_money():
            try:
                amount = int(add_money_entry.get())
                if amount < 0:
                    messagebox.showerror("Error", "Please enter a positive amount")
                    return

                with open(f"{username}.txt", "r+") as file:
                    encrypted_password, money_count = file.read().splitlines()
                    money_count = int(money_count) + amount
                    file.seek(0)
                    file.truncate()
                    file.write(f"{encrypted_password}\n{money_count}")

                messagebox.showinfo("Success", f"Added ${amount} to your account!")
                update_money_label()

                transactions = [f"{username} added ${amount}"]
                merkle_root = custom_hash("".join(transactions))
                new_block = Block(len(self.blockchain.chain), self.blockchain.get_latest_block().hash, "timestamp_placeholder", transactions, merkle_root)
                self.blockchain.add_block(new_block)
                messagebox.showinfo("Success", "Transaction added to the blockchain!")

            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number")

        ttk.Button(user_window, text="Add Money", command=add_money).pack(pady=10)

        share_money_frame = ttk.Frame(user_window)
        share_money_frame.pack(pady=20, fill=BOTH, expand=True)

        ttk.Label(share_money_frame, text="Share Money With:").grid(row=0, column=0, sticky=W, pady=5)
        share_username_entry = ttk.Entry(share_money_frame)
        share_username_entry.grid(row=0, column=1, pady=5, sticky=EW)

        ttk.Label(share_money_frame, text="Amount:").grid(row=1, column=0, sticky=W, pady=5)
        share_amount_entry = ttk.Entry(share_money_frame)
        share_amount_entry.grid(row=1, column=1, pady=5, sticky=EW)

        def share_money():
            share_username = share_username_entry.get()
            try:
                share_amount = int(share_amount_entry.get())
                if share_amount <= 0:
                    messagebox.showerror("Error", "Please enter a positive amount")
                    return

            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number")

        ttk.Button(share_money_frame, text="Share Money", command=share_money).grid(row=2, columnspan=2, pady=10)

        transactions_label = ttk.Label(user_window, text="Blockchain Transactions:")
        transactions_label.pack(pady=5)

        transactions_text = scrolledtext.ScrolledText(user_window, height=10)
        transactions_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        for block in self.blockchain.chain:
            transactions_text.insert(tk.END, f"Block {block.index}: {block.transactions}\n")

if __name__ == "__main__":
    root = ttk.Window(themename="litera")
    app = EnhancedUI(root)
    root.mainloop()
