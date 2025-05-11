import re
import tkinter as tk
from tkinter import messagebox


def assess_password_strength(password):
    length_pattern = r'.{8,}'
    lowercase_pattern = r'[a-z]'
    uppercase_pattern = r'[A-Z]'
    digit_pattern = r'\d'
    special_char_pattern = r'[!@#$%^&*(),.?":{}|<>]'
    weak_patterns = [r'123', r'abc', r'password', r'qwerty', r'0000']

    score = 0
    tips = []

    if re.search(length_pattern, password):
        score += 1
    else:
        tips.append("Use at least 8 characters.")

    if re.search(lowercase_pattern, password):
        score += 1
    else:
        tips.append("Include lowercase letters.")

    if re.search(uppercase_pattern, password):
        score += 1
    else:
        tips.append("Include uppercase letters.")

    if re.search(digit_pattern, password):
        score += 1
    else:
        tips.append("Include digits.")

    if re.search(special_char_pattern, password):
        score += 1
    else:
        tips.append("Include special characters like !@#$%^&*")

    for pattern in weak_patterns:
        if re.search(pattern, password.lower()):
            tips.append("Avoid common patterns like '123', 'abc', 'password'")
            score -= 1
            break

    if score <= 2:
        strength = "Weak"
    elif score in [3, 4]:
        strength = "Moderate"
    else:
        strength = "Strong"

    return strength, tips

def check_password():
    password = entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    
    strength, tips = assess_password_strength(password)
    result_label.config(text=f"Password Strength: {strength}", fg="green" if strength == "Strong" else "orange" if strength == "Moderate" else "red")

    tips_text.delete("1.0", tk.END)
    if tips:
        tips_text.insert(tk.END, "Tips to improve your password:\n")
        for tip in tips:
            tips_text.insert(tk.END, f"• {tip}\n")


root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x300")
root.resizable(False, False)
tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, width=30, show="*", font=("Arial", 12))
entry.pack()

tk.Button(root, text="Check Strength", command=check_password, font=("Arial", 12)).pack(pady=10)
result_label = tk.Label(root, text="", font=("Arial", 12, "bold"))
result_label.pack()
tips_text = tk.Text(root, height=6, width=45, font=("Arial", 10))
tips_text.pack(pady=5)
root.mainloop()
