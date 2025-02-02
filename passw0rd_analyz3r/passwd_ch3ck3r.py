import tkinter as tk
from tkinter import messagebox
import secrets
import string
import re
import hashlib
import requests

# Password Strength Meter Colors
STRENGTH_COLORS = {
    1: "#FF4C4C",  # Weak (Red)
    2: "#FFA500",  # Fair (Orange)
    3: "#FFD700",  # Good (Yellow)
    4: "#9ACD32",  # Strong (Green)
    5: "#008000"   # Very Strong (Dark Green)
}

def generate_password():
    """Generate and display a strong password."""
    length = 12  
    new_password = generate_password_logic(length)
    entry.delete(0, tk.END)
    entry.insert(0, new_password)
    update_strength_meter(new_password)

def generate_password_logic(length=12):
    """Generate a secure password of given length."""
    if length < 8:
        length = 8  

    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = string.punctuation
    all_chars = lower + upper + digits + special

    password = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    password += [secrets.choice(all_chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password)

    return "".join(password)

def copy_to_clipboard():
    """Copy the generated password to clipboard."""
    password = entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()  
        messagebox.showinfo("Copied", "Password copied to clipboard!")

def check_pwned_password(password):
    """Check if the password has been leaked using Have I Been Pwned API."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    first_five, rest = sha1_hash[:5], sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{first_five}"
    response = requests.get(url)

    if response.status_code == 200:
        hashes = response.text.splitlines()
        for line in hashes:
            hash_suffix, count = line.split(':')
            if rest == hash_suffix:
                return int(count)
    return 0  

def check_password_strength(password):
    """Evaluate password strength based on various criteria."""
    strength = 0
    criteria = [
        (r'.{8,}', "At least 8 characters long"),
        (r'[A-Z]', "Contains an uppercase letter"),
        (r'[a-z]', "Contains a lowercase letter"),
        (r'\d', "Contains a number"),
        (r'[!@#$%^&*(),.?":{}|<>]', "Contains a special character")
    ]

    for pattern, message in criteria:
        if re.search(pattern, password):
            strength += 1

    return strength, len(criteria)

def update_strength_meter(password):
    """Update the strength meter dynamically."""
    strength, total_criteria = check_password_strength(password)
    strength_meter.config(text=f"Strength: {strength}/{total_criteria}")
    strength_meter.config(bg=STRENGTH_COLORS.get(strength, "#FF4C4C"))

def check_password():
    """Analyze password strength and check for breaches."""
    password = entry.get()
    strength, total_criteria = check_password_strength(password)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    breach_count = check_pwned_password(password)

    strength_msg = f"Password Strength: {strength}/{total_criteria}\nHashed Password (SHA-256):\n{hashed_password}"
    
    if breach_count > 0:
        strength_msg += f"\n⚠️ WARNING: This password has been found in {breach_count} data breaches!\nChange it immediately."
    else:
        strength_msg += "\n✅ Safe: This password has not been found in any known breaches."

    messagebox.showinfo("Password Strength", strength_msg)

def toggle_password_visibility():
    """Toggle between showing and hiding the password."""
    if show_password_var.get():
        entry.config(show="")  # Show password
    else:
        entry.config(show="*")  # Hide password

# GUI Setup
root = tk.Tk()
root.title("Password Strength Analyzer")

tk.Label(root, text="Enter Password:").pack()
entry = tk.Entry(root, show="*", width=30)
entry.pack()
entry.bind("<KeyRelease>", lambda event: update_strength_meter(entry.get()))  

# Show/Hide Password Checkbox
show_password_var = tk.BooleanVar()
show_password_check = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
show_password_check.pack()

strength_meter = tk.Label(root, text="Strength: 0/5", bg="#FF4C4C", fg="white", width=20)
strength_meter.pack()

tk.Button(root, text="Check Strength", command=check_password).pack()
tk.Button(root, text="Generate Password", command=generate_password).pack()
tk.Button(root, text="Copy Password", command=copy_to_clipboard).pack()

root.mainloop()
