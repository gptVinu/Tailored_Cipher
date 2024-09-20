import tkinter as tk
from tkinter import messagebox
import string
import random
import pyperclip

# Global variables to store substitution dictionary, transposition key, and positions of random characters
substitution_dict = {}
transposition_key = []
positions_of_random_chars = []

# Function to encrypt the text
def encrypt_text():
    global substitution_dict, transposition_key, positions_of_random_chars
    plaintext = entry_plaintext.get()
    if not plaintext:
        messagebox.showerror("Input Error", "Please enter plaintext to encrypt.")
        return
    
    # Create a substitution alphabet (shuffled alphabet)
    alphabet = list(string.ascii_lowercase)
    shuffled_alphabet = alphabet[:]
    random.shuffle(shuffled_alphabet)
    substitution_dict = dict(zip(alphabet, shuffled_alphabet))
    
    # Create a transposition key
    transposition_key = list(range(len(plaintext)))
    random.shuffle(transposition_key)
    
    # Substitute characters in plaintext
    substituted_text = ''.join(substitution_dict.get(char, char) for char in plaintext.lower())
    
    # Transpose the substituted text
    transposed_text = ''.join([substituted_text[i] for i in transposition_key])
    
    # Generate random positions for characters to be added
    positions_of_random_chars = sorted(random.sample(range(len(transposed_text) + 1), len(transposed_text) // 2))
    encrypted_message = list(transposed_text)
    random_chars = ''.join(random.choices(string.ascii_letters, k=len(positions_of_random_chars)))
    
    for pos, char in zip(positions_of_random_chars, random_chars):
        encrypted_message.insert(pos, char)
    
    encrypted_message = ''.join(encrypted_message)
    
    # Display encrypted message and positions of random characters
    output_encrypted_message.config(state=tk.NORMAL)
    output_encrypted_message.delete("1.0", tk.END)
    output_encrypted_message.insert(tk.END, encrypted_message)
    output_encrypted_message.config(state=tk.DISABLED)
    
    output_positions.config(state=tk.NORMAL)
    output_positions.delete("1.0", tk.END)
    output_positions.insert(tk.END, str(positions_of_random_chars))
    output_positions.config(state=tk.DISABLED)

# Function to decrypt the text
def decrypt_text():
    global substitution_dict, transposition_key, positions_of_random_chars
    
    ciphertext = entry_ciphertext.get()
    positions_str = entry_positions.get()
    
    if not ciphertext or not positions_str:
        messagebox.showerror("Input Error", "Please provide ciphertext and positions of random characters.")
        return
    
    # Parse the positions of random characters
    try:
        positions_of_random_chars = eval(positions_str)
        if not isinstance(positions_of_random_chars, list):
            raise ValueError
    except:
        messagebox.showerror("Input Error", "Positions must be a list of integers.")
        return
    
    # Remove the random characters from the ciphertext
    ciphertext_list = list(ciphertext)
    for pos in reversed(positions_of_random_chars):
        del ciphertext_list[pos]
    
    transposed_text = ''.join(ciphertext_list)
    
    # Reverse the transposition
    reverse_key = sorted(range(len(transposition_key)), key=lambda k: transposition_key[k])
    substituted_text = ''.join([transposed_text[i] for i in reverse_key])
    
    # Reverse the substitution
    reverse_substitution = {v: k for k, v in substitution_dict.items()}
    decrypted_message = ''.join(reverse_substitution.get(char, char) for char in substituted_text.lower())
    
    # Display the decrypted message
    output_decrypted_message.config(state=tk.NORMAL)
    output_decrypted_message.delete("1.0", tk.END)
    output_decrypted_message.insert(tk.END, decrypted_message)
    output_decrypted_message.config(state=tk.DISABLED)

# Function to clear all the fields
def clear_all():
    global substitution_dict, transposition_key, positions_of_random_chars
    
    entry_plaintext.delete(0, tk.END)
    output_encrypted_message.config(state=tk.NORMAL)
    output_encrypted_message.delete("1.0", tk.END)
    output_encrypted_message.config(state=tk.DISABLED)
    
    output_positions.config(state=tk.NORMAL)
    output_positions.delete("1.0", tk.END)
    output_positions.config(state=tk.DISABLED)
    
    entry_ciphertext.delete(0, tk.END)
    entry_positions.delete(0, tk.END)
    output_decrypted_message.config(state=tk.NORMAL)
    output_decrypted_message.delete("1.0", tk.END)
    output_decrypted_message.config(state=tk.DISABLED)
    
    # Clear global variables
    substitution_dict = {}
    transposition_key = []
    positions_of_random_chars = []

# Function to copy encrypted message to clipboard
def copy_encrypted_message():
    encrypted_message = output_encrypted_message.get("1.0", tk.END).strip()
    pyperclip.copy(encrypted_message)
    messagebox.showinfo("Copied", "Encrypted message copied to clipboard!")

# Function to copy random character positions to clipboard
def copy_positions():
    positions = output_positions.get("1.0", tk.END).strip()
    pyperclip.copy(positions)
    messagebox.showinfo("Copied", "Positions copied to clipboard!")

# Function to paste ciphertext from clipboard
def paste_ciphertext():
    clipboard_text = pyperclip.paste()
    entry_ciphertext.delete(0, tk.END)
    entry_ciphertext.insert(0, clipboard_text)

# Function to paste positions from clipboard
def paste_positions():
    clipboard_text = pyperclip.paste()
    entry_positions.delete(0, tk.END)
    entry_positions.insert(0, clipboard_text)

# GUI Setup
root = tk.Tk()
root.title("Tailored Cipher Tool")
root.geometry("950x550") 
root.configure(bg="#f0f8ff")  

# Styling - Adjusted font sizes
bg_color = "#f0f8ff"
button_color = "#4CAF50"
button_font = ("Arial", 10, "bold")  
heading_font = ("Arial", 12, "bold")  
label_font = ("Arial", 10)  
entry_font = ("Arial", 10)  
text_font = ("Arial", 10)  

# Main Frame for layout
frame = tk.Frame(root, bg=bg_color)
frame.pack(fill="both", expand=True)

# Welcome Heading
welcome_label = tk.Label(frame, text="Welcome to My Tailored Cipher", font=("Arial", 16, "bold"), bg=bg_color)
welcome_label.grid(row=0, column=0, columnspan=3, pady=15)

# Left section (Encryption)
left_frame = tk.Frame(frame, bg=bg_color)
left_frame.grid(row=1, column=0, padx=10, pady=10)

label_encrypt = tk.Label(left_frame, text="Encryption", font=heading_font, bg=bg_color)
label_encrypt.grid(row=0, column=0, columnspan=3, pady=10)

label_plaintext = tk.Label(left_frame, text="Enter Plaintext:", bg=bg_color, font=label_font)
label_plaintext.grid(row=1, column=0, sticky="e")
entry_plaintext = tk.Entry(left_frame, width=25, font=entry_font)
entry_plaintext.grid(row=1, column=1)

button_encrypt = tk.Button(left_frame, text="Encrypt", bg=button_color, fg="white", font=button_font, command=encrypt_text)
button_encrypt.grid(row=2, column=0, columnspan=3, pady=10)

label_encrypted_message = tk.Label(left_frame, text="Encrypted Message:", bg=bg_color, font=label_font)
label_encrypted_message.grid(row=3, column=0, sticky="e")
output_encrypted_message = tk.Text(left_frame, height=1, width=25, state=tk.DISABLED, font=text_font)
output_encrypted_message.grid(row=3, column=1)

button_copy_encrypted = tk.Button(left_frame, text="Copy", bg=button_color, fg="white", font=button_font, command=copy_encrypted_message)
button_copy_encrypted.grid(row=3, column=2)

label_positions = tk.Label(left_frame, text="Positions of Random Characters:", bg=bg_color, font=label_font)
label_positions.grid(row=4, column=0, sticky="e")
output_positions = tk.Text(left_frame, height=1, width=25, state=tk.DISABLED, font=text_font)
output_positions.grid(row=4, column=1)

button_copy_positions = tk.Button(left_frame, text="Copy", bg=button_color, fg="white", font=button_font, command=copy_positions)
button_copy_positions.grid(row=4, column=2)

# Right section (Decryption)
right_frame = tk.Frame(frame, bg=bg_color)
right_frame.grid(row=1, column=1, padx=10, pady=10)

label_decrypt = tk.Label(right_frame, text="Decryption", font=heading_font, bg=bg_color)
label_decrypt.grid(row=0, column=0, columnspan=3, pady=10)

label_ciphertext = tk.Label(right_frame, text="Enter Ciphertext:", bg=bg_color, font=label_font)
label_ciphertext.grid(row=1, column=0, sticky="e")
entry_ciphertext = tk.Entry(right_frame, width=25, font=entry_font)
entry_ciphertext.grid(row=1, column=1)

button_paste_ciphertext = tk.Button(right_frame, text="Paste", bg=button_color, fg="white", font=button_font, command=paste_ciphertext)
button_paste_ciphertext.grid(row=1, column=2)

label_positions = tk.Label(right_frame, text="Enter Positions of Random Characters (as list):", bg=bg_color, font=label_font)
label_positions.grid(row=2, column=0, sticky="e")
entry_positions = tk.Entry(right_frame, width=25, font=entry_font)
entry_positions.grid(row=2, column=1)

button_paste_positions = tk.Button(right_frame, text="Paste", bg=button_color, fg="white", font=button_font, command=paste_positions)
button_paste_positions.grid(row=2, column=2)

button_decrypt = tk.Button(right_frame, text="Decrypt", bg=button_color, fg="white", font=button_font, command=decrypt_text)
button_decrypt.grid(row=3, column=0, columnspan=3, pady=10)

label_decrypted_message = tk.Label(right_frame, text="Decrypted Message:", bg=bg_color, font=label_font)
label_decrypted_message.grid(row=4, column=0, sticky="e")
output_decrypted_message = tk.Text(right_frame, height=1, width=25, state=tk.DISABLED, font=text_font)
output_decrypted_message.grid(row=4, column=1)

# Exit and Clear Buttons at the bottom
button_clear = tk.Button(root, text="Clear", bg="#FF6347", fg="white", font=button_font, command=clear_all)
button_clear.pack(side=tk.LEFT, padx=50, pady=20)

button_exit = tk.Button(root, text="Exit", bg="#FF6347", fg="white", font=button_font, command=root.quit)
button_exit.pack(side=tk.RIGHT, padx=50, pady=20)

root.mainloop()
