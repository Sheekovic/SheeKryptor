import base64
import hashlib
import json
import os
import secrets
import sqlite3
import string
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
from ttkthemes import ThemedTk
import tkinter.font as tkFont
import pyotp
import configparser

from archive_core import ArchiveError, create_zip, extract_zip
from crypto_core import CryptoError, decrypt_file as decrypt_path
from crypto_core import encrypt_file as encrypt_path

APP_NAME = "SheeKryptor"
APP_VERSION = "3.0.0"
REQUEST_TIMEOUT = 20

# Database Setup
conn = sqlite3.connect("2fa_accounts.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    username TEXT NOT NULL,
    key TEXT NOT NULL,
    time_based INTEGER NOT NULL
)
""")
conn.commit()

# Add a Text widget for logs in the Encryptor Tab
log_output_text = None  # We'll define this later in the GUI setup

# Define output directory
encrypted_output_directory = "encrypted_files"
decrypted_output_directory = "decrypted_files"

# Global reference for GUI components
squashit_progress_bar = None
squashit_result_label = None

# Initialize ConfigParser
config = configparser.ConfigParser()
# Read settings from the INI file
config.read("settings.ini")
# Get settings with defaults if not found
# Default theme is 'equilux'
settings_theme = config.get("Settings", "theme", fallback="equilux")
settings_font_style = config.get(
    "Settings", "font_style", fallback="Segoe UI")
settings_font_size = config.get(
    "Settings", "font_size", fallback="11")

# Function to generate a strong password


def generate_password(length):
    if length < 12:
        messagebox.showwarning(
            "Warning", "Password length should be at least 12 characters.")
        return None

    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# Function to update the password entry with the generated password


def create_password():
    try:
        length = int(password_length_entry.get())
        password = generate_password(length)
        if password:
            password_entry.delete(0, 'end')
            password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror(
            "Error", "Please enter a valid number for password length.")

# Function to generate a personalized password


def generate_personalized_password():
    name = name_entry.get().strip()
    dob = dob_entry.get().strip()
    try:
        length = int(personal_password_length_entry.get())
        if length < 12:
            messagebox.showwarning(
                "Warning", "Password length should be at least 12 characters.")
            return

        if not name or not dob:
            messagebox.showwarning(
                "Warning", "Please provide both Name and Date of Birth.")
            return

        # Personal details are mixed into the character pool, but secure system
        # randomness supplies the password entropy. They never seed a PRNG.
        personalized_seed = hashlib.sha256(
            (name + dob).encode('utf-8')).hexdigest()
        characters = string.ascii_letters + string.digits + string.punctuation
        characters += personalized_seed
        password = ''.join(secrets.choice(characters) for _ in range(length))

        personal_password_entry.delete(0, 'end')
        personal_password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror(
            "Error", "Please enter a valid number for password length.")


def encrypt_file(input_file, output_file, password):
    try:
        log("Starting authenticated encryption...")
        log(f"Reading input file: {input_file}")
        encrypt_path(input_file, output_file, password)
        log(f"Output file saved successfully: {output_file}")

        messagebox.showinfo(
            "Success", f"Encryption completed. Output saved to:\n{output_file}")

    except (CryptoError, OSError) as e:
        log(f"Error occurred during encryption: {e}")
        messagebox.showerror("Error", f"Failed to encrypt file: {e}")

# Function to decrypt a file and log the actions


def decrypt_file(input_file, output_file, password):
    try:
        decryptor_log.insert("end", "Starting decryption process...\n")
        used_legacy_format = decrypt_path(input_file, output_file, password)
        decryptor_log.insert(
            "end", f"Decryption completed. Output saved to: {output_file}\n")

        if used_legacy_format:
            decryptor_log.insert(
                "end",
                "Warning: this file used the unauthenticated legacy format. "
                "Encrypt the recovered file again to upgrade it.\n",
            )
            messagebox.showwarning(
                "Legacy encrypted file",
                "The file was recovered using SheeKryptor's legacy format. "
                "Encrypt it again to upgrade it to authenticated encryption.",
            )

        messagebox.showinfo(
            "Success", f"Decryption completed. Output saved to:\n{output_file}")

    except (CryptoError, OSError) as e:
        decryptor_log.insert("end", f"Error occurred during decryption: {e}\n")
        messagebox.showerror("Error", f"Failed to decrypt file: {e}")


# Function to browse input file
def browse_input_file_decrypt():
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        decryptor_input_file_entry.delete(0, "end")  # Clear the entry
        # Insert the selected file path
        decryptor_input_file_entry.insert(0, file_path)
    else:
        messagebox.showwarning("Warning", "No file selected.")


def browse_input_file_encrypt():
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        encryptor_input_file_entry.delete(0, "end")  # Clear the entry
        # Insert the selected file path
        encryptor_input_file_entry.insert(0, file_path)
    else:
        messagebox.showwarning("Warning", "No file selected.")

# Function to generate output file path with 'encrypted' or 'decrypted' appended


def get_output_file_path(input_file, is_encryption=True):
    base_name = os.path.basename(input_file)
    name, ext = os.path.splitext(base_name)

    if is_encryption:
        new_name = f"{base_name}.skrypt"
        output_directory = encrypted_output_directory
    else:
        new_name = base_name[:-8] if base_name.lower().endswith(".skrypt") else f"{name}_decrypted{ext}"
        output_directory = decrypted_output_directory

    # Ensure the output directory exists
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    output_path = os.path.join(output_directory, new_name)
    candidate_name, candidate_ext = os.path.splitext(new_name)
    counter = 1
    while os.path.exists(output_path):
        output_path = os.path.join(
            output_directory, f"{candidate_name}_{counter}{candidate_ext}"
        )
        counter += 1

    return output_path

# Function to start encryption


def start_encryption():
    input_file = encryptor_input_file_entry.get()
    password = encryptor_password_entry.get()

    if not input_file or not os.path.exists(input_file):
        messagebox.showerror("Error", "Invalid input file path.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    output_file = get_output_file_path(input_file, is_encryption=True)
    encrypt_file(input_file, output_file, password)

# Function to log messages to the Text widget


def log(message):
    log_output_text.insert('end', message + '\n')  # Insert the log message
    log_output_text.yview('end')  # Scroll to the end

# Function to start decryption


def start_decryption():
    input_file = decryptor_input_file_entry.get()
    password = decryptor_password_entry.get()

    if not input_file or not os.path.exists(input_file):
        messagebox.showerror("Error", "Invalid input file path.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    output_file = get_output_file_path(input_file, is_encryption=False)
    decrypt_file(input_file, output_file, password)

# Function to load settings


def load_settings():
    config = configparser.ConfigParser()
    config.read("settings.ini")
    if "Settings" in config:
        # Apply saved theme
        saved_theme = config["Settings"].get("theme", "equilux")
        if saved_theme in style.theme_names():
            style.theme_use(saved_theme)

        # Apply saved font size and style
        saved_font_size = config["Settings"].get("font_size", "16")
        saved_font_style = config["Settings"].get(
            "font_style", "OCR A Extended")
        style.configure("TLabel", font=(saved_font_style, saved_font_size))
        style.configure("TButton", font=(saved_font_style, saved_font_size))
        style.configure("TEntry", font=(saved_font_style, saved_font_size))
        style.configure("TFrame", font=(saved_font_style, saved_font_size))
        style.configure("TCombobox", font=(saved_font_style, saved_font_size))
        style.configure("TNotebook", font=(saved_font_style, saved_font_size))
        style.configure("TCanvas", font=(saved_font_style, saved_font_size))
        style.configure("TCheckbutton", font=(
            saved_font_style, saved_font_size))
        style.configure("TScrollbar", font=(saved_font_style, saved_font_size))
        style.configure("Treeview", font=(saved_font_style, saved_font_size))
        style.configure("TRadiobutton", font=(
            saved_font_style, saved_font_size))
        style.configure("TProgressbar", font=(
            saved_font_style, saved_font_size))
        # Refresh the application
        root.update()

# Function to update settings


def update_settings():
    selected_theme = theme_combobox.get()
    style.theme_use(selected_theme)

    selected_font_size = font_size_combobox.get()
    selected_font_style = font_style_combobox.get()

    style.configure("TLabel", font=(selected_font_style, selected_font_size))
    style.configure("TButton", font=(selected_font_style, selected_font_size))
    style.configure("TEntry", font=(selected_font_style, selected_font_size))
    style.configure("TFrame", font=(selected_font_style, selected_font_size))
    style.configure("TCombobox", font=(
        selected_font_style, selected_font_size))
    style.configure("TNotebook", font=(
        selected_font_style, selected_font_size))
    style.configure("TCanvas", font=(selected_font_style, selected_font_size))
    style.configure("TCheckbutton", font=(
        selected_font_style, selected_font_size))
    style.configure("TScrollbar", font=(
        selected_font_style, selected_font_size))
    style.configure("Treeview", font=(selected_font_style, selected_font_size))
    style.configure("TRadiobutton", font=(
        selected_font_style, selected_font_size))
    style.configure("TProgressbar", font=(
        selected_font_style, selected_font_size))

    # Refresh the application
    root.update()

    # Save settings to settings.ini
    config = configparser.ConfigParser()
    config["Settings"] = {
        "theme": selected_theme,
        "font_size": selected_font_size,
        "font_style": selected_font_style
    }
    with open("settings.ini", "w") as f:
        config.write(f)


def send_api_request():
    api_url = api_url_entry.get()
    request_type = request_type_combobox.get()
    headers = headers_entry.get()
    auth_token = auth_token_entry.get()
    request_body = request_body_entry.get()

    headers_dict = {}
    try:
        if headers:
            # Parse headers as JSON if provided
            headers_dict = json.loads(headers)
    except json.JSONDecodeError:
        messagebox.showerror(
            "Error", "Invalid headers format. Please provide valid JSON.")

    # Add Authorization token to headers if provided
    if auth_token:
        headers_dict["Authorization"] = f"Bearer {auth_token}"

    try:
        # Send the API request based on the selected type
        if request_type == "GET":
            response = requests.get(
                api_url, headers=headers_dict, timeout=REQUEST_TIMEOUT
            )
        elif request_type == "POST":
            response = requests.post(api_url, json=json.loads(
                request_body), headers=headers_dict, timeout=REQUEST_TIMEOUT)
        elif request_type == "PUT":
            response = requests.put(api_url, json=json.loads(
                request_body), headers=headers_dict, timeout=REQUEST_TIMEOUT)
        elif request_type == "DELETE":
            response = requests.delete(
                api_url, headers=headers_dict, timeout=REQUEST_TIMEOUT
            )

        # Display the response in the response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Response Code: {
                             response.status_code}\n")
        response_text.insert("insert", f"Response Body:\n{response.text}")

    except requests.exceptions.RequestException as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Request failed: {e}")
    except json.JSONDecodeError as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert(
            "insert", f"Invalid request body format. Please provide valid JSON, {e}")
    except Exception as e:
        # display error message in response area
        response_text.delete(1.0, "end")  # Clear previous response
        response_text.insert("insert", f"Failed to send API request: {e}")

# Optional: Save Results Button (save to a text file)


def save_results():
    try:
        response_data = response_text.get(1.0, "end")
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(response_data)
            messagebox.showinfo("Success", f"Results saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save results: {e}")

# Function to add an account


def add_account():
    provider = provider_entry.get()
    username = username_entry.get()
    key = key_entry.get()
    # Remove spaces from the key
    key = key.replace(" ", "")
    time_based = time_based_var.get()

    if not username or not key:
        messagebox.showerror("Error", "Username and Key are required!")
        return

    try:
        # Validate Key
        otp = pyotp.TOTP(key)
        otp.now()  # Test generation
    except:
        messagebox.showerror("Error", "Invalid 2FA Key!")
        return

    # Generate the custom id: first two letters of provider + first two letters of username
    custom_id = provider[:2].upper() + username[:2].upper()

    # Get the current max number from the table to increment the ID
    cursor.execute(
        "SELECT MAX(SUBSTR(id, 5, LENGTH(id))) FROM accounts WHERE id LIKE ?", (custom_id + '%',))
    max_id_suffix = cursor.fetchone()[0]

    # If no records exist, start from 1
    if max_id_suffix is None:
        id_suffix = 1
    else:
        id_suffix = int(max_id_suffix) + 1

    # Create the final unique ID
    final_id = custom_id + str(id_suffix)

    cursor.execute("INSERT INTO accounts (id, provider, username, key, time_based) VALUES (?, ?, ?, ?, ?)",
                   (final_id, provider, username, key, time_based))
    conn.commit()
    refresh_accounts()
    messagebox.showinfo("Success", "Account added successfully!")

# Function to delete account from the database


def delete_account():
    selected_account = account_combobox.get()

    if not selected_account:
        messagebox.showerror("Error", "No account selected for deletion!")
        return

    # Delete the account from the database based on the selected id
    cursor.execute("DELETE FROM accounts WHERE id = ?", (selected_account,))
    conn.commit()
    refresh_accounts()
    messagebox.showinfo("Success", "Account deleted successfully!")


def refresh_accounts():
    # Delete all rows in the table
    for row in accounts_table.get_children():
        accounts_table.delete(row)

    # Fetch accounts from the database, including the id
    cursor.execute(
        "SELECT id, provider, username, key, time_based FROM accounts")
    accounts = cursor.fetchall()  # Store the accounts to use later

    # Insert rows into the table
    for account in accounts:
        otp = pyotp.TOTP(account[3])
        current_otp = otp.now()
        accounts_table.insert("", "end", values=(
            account[0], account[1], account[2], current_otp))

    # Update the combobox values with account ids
    account_combobox['values'] = [account[0] for account in accounts]


def update_otps():
    for child in accounts_table.get_children():
        item = accounts_table.item(child)
        values = list(item['values'])
        account_id = values[0]

        cursor.execute(
            "SELECT key FROM accounts WHERE id = ?", (account_id,))
        account = cursor.fetchone()
        if account:
            otp = pyotp.TOTP(account[0])
            current_otp = otp.now()
            values[3] = current_otp
            accounts_table.item(child, values=values)

    root.after(1000, update_otps)  # Refresh OTPs every second


def unsquashit(input_file, output_dir):
    """Extract a ZIP archive into a dedicated directory."""
    try:
        if isinstance(input_file, list):
            input_file = input_file[0] if input_file else ""
        archive_path = os.path.abspath(input_file)
        if not output_dir:
            output_dir = os.path.splitext(archive_path)[0]
        extracted = extract_zip(archive_path, output_dir)
        result = f"Extracted {len(extracted)} item(s) to {output_dir}"
        unsquashit_result_label.config(text=result, foreground=green)
        return result
    except (ArchiveError, OSError) as e:
        result = f"Extraction failed: {e}"
        unsquashit_result_label.config(text=result, foreground=red)
        return result


def squashit(input_files, output_file, compression_level=9):
    """Create a standard ZIP archive from the selected files."""
    try:
        def update_progress(value):
            squashit_progress_bar["value"] = value
            root.update_idletasks()

        file_hash = create_zip(
            input_files,
            output_file,
            compression_level=compression_level,
            progress=update_progress,
        )
        result = f"ZIP archive created. SHA-256: {file_hash}"
        squashit_result_label.config(text=result, foreground=green)
        return result
    except (ArchiveError, OSError) as e:
        result = f"Compression failed: {e}"
        squashit_result_label.config(text=result, foreground=red)
        return result


def browse_file(entry):
    """Browse and select files."""
    file_paths = filedialog.askopenfilenames()
    if file_paths:
        entry.delete(0, tk.END)
        entry.insert(0, ', '.join(file_paths))


def browse_folder(entry):
    """Browse and select a folder."""
    folder_path = filedialog.askdirectory()
    if folder_path:
        entry.delete(0, tk.END)
        entry.insert(0, folder_path)


def browse_output(entry, operation_type):
    """Browse and select the output file or directory based on the operation."""
    if operation_type == 'SquashIt':
        output_path = filedialog.asksaveasfilename(
            defaultextension=".zip",
            filetypes=[("ZIP Archives", "*.zip"), ("All Files", "*.*")],
        )
    elif operation_type == 'UnSquashIt':
        # For UnSquashIt, allow the user to select a folder for decompressed files
        output_path = filedialog.askdirectory()  # Asking for a directory path

    if output_path:
        entry.delete(0, tk.END)
        entry.insert(0, output_path)

# Function to handle conversion ConvertX


def convertx(input_files, conversion_type):
    # Clear the result text box before starting a new conversion
    convertx_result_text.delete(1.0, tk.END)

    # Process each input file
    for input_file in input_files:
        # Get the folder of the input file
        folder_path = os.path.dirname(input_file)
        # Get the filename without path
        base_name = os.path.basename(input_file)

        # Add _{conversion_type} to the output filename
        if conversion_type == "Image to Base64":
            output_file = os.path.join(
                folder_path, f"{os.path.splitext(base_name)[0]}_base64.txt")
        elif conversion_type == "Base64 to Image":
            output_file = os.path.join(
                folder_path, f"{os.path.splitext(base_name)[0]}_image.png")
        elif conversion_type == "Text Encoding":
            output_file = os.path.join(folder_path, f"{os.path.splitext(
                base_name)[0]}_encoded{os.path.splitext(base_name)[1]}")
        elif conversion_type == "Base64 to Text":
            output_file = os.path.join(folder_path, f"{os.path.splitext(
                base_name)[0]}_decoded{os.path.splitext(base_name)[1]}")

        if conversion_type == "Image to Base64":
            convert_image_to_base64(input_file, output_file)
        elif conversion_type == "Base64 to Image":
            convert_base64_to_image(input_file, output_file)
        elif conversion_type == "Text Encoding":
            convert_text_encoding(input_file, output_file)
        elif conversion_type == "Base64 to Text":
            convert_base64_to_text(input_file, output_file)

        # Display output file location in result label
        convertx_result_label.config(text=f"Output saved to: {output_file}")

# Conversion Function: Image to Base64


def convert_image_to_base64(input_file, output_file):
    try:
        with open(input_file, "rb") as f:
            data = f.read()
            base64_data = base64.b64encode(data).decode("utf-8")
            with open(output_file, "w") as f_out:
                f_out.write(base64_data)

        # Update result text dynamically
        convertx_result_text.insert(tk.END, f"Image {
                                    input_file} converted to Base64 successfully! Saved to {output_file}\n")
        convertx_result_text.yview(tk.END)  # Auto-scroll to the latest result
    except Exception as e:
        convertx_result_text.insert(tk.END, f"Error: {str(e)}\n")
        convertx_result_text.yview(tk.END)

# Conversion Function: Base64 to Image


def convert_base64_to_image(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            base64_data = f.read()
            decoded_data = base64.b64decode(base64_data)
            with open(output_file, "wb") as f_out:
                f_out.write(decoded_data)
        # Update result text dynamically
        convertx_result_text.insert(tk.END, f"Base64 file {
                                    input_file} converted to image successfully! Saved to {output_file}\n")
        convertx_result_text.yview(tk.END)  # Auto-scroll to the latest result
    except Exception as e:
        convertx_result_text.insert(tk.END, f"Error: {str(e)}\n")
        convertx_result_text.yview(tk.END)

# Conversion Function: Text Encoding


def convert_text_encoding(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            text_data = f.read()
            encoded_data = text_data.encode("utf-8")
            with open(output_file, "wb") as f_out:
                f_out.write(encoded_data)
        # Update result text dynamically
        convertx_result_text.insert(tk.END, f"Text from {
                                    input_file} encoded to UTF-8 successfully! Saved to {output_file}\n")
        convertx_result_text.yview(tk.END)  # Auto-scroll to the latest result
    except Exception as e:
        convertx_result_text.insert(tk.END, f"Error: {str(e)}\n")
        convertx_result_text.yview(tk.END)

# Conversion Function: Base64 to Text


def convert_base64_to_text(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            base64_data = f.read()
            decoded_data = base64.b64decode(base64_data)
            with open(output_file, "w") as f_out:
                f_out.write(decoded_data.decode("utf-8"))
        # Update result text dynamically
        convertx_result_text.insert(tk.END, f"Base64 file {
                                    input_file} decoded to text successfully! Saved to {output_file}\n")
        convertx_result_text.yview(tk.END)  # Auto-scroll to the latest result
    except Exception as e:
        convertx_result_text.insert(tk.END, f"Error: {str(e)}\n")
        convertx_result_text.yview(tk.END)

# Function to generate temporary mail


def generate_temp_mail():
    # Declare globals for use in `refresh_messages`
    global headers, messages_url, messages_result_text
    # Get Available Domains
    domain_response = requests.get(
        "https://api.mail.tm/domains", timeout=REQUEST_TIMEOUT
    )
    domain_response.raise_for_status()  # Check for request errors
    domain_data = domain_response.json()

    # Get the first domain string
    domain = domain_data['hydra:member'][0]['domain']

    # Get Name and Password from Entry Fields
    name = name_entry.get().strip()
    password = password_entry.get().strip()

    # Create an account
    account_url = "https://api.mail.tm/accounts"
    account_data = {
        "address": name + "@" + domain,
        "password": password
    }
    account_response = requests.post(
        account_url, json=account_data, timeout=REQUEST_TIMEOUT
    )
    account_response.raise_for_status()
    account_details = account_response.json()

    # print account_details in account_id_label
    account_id_label.config(text="Account ID: " + account_details['id'])
    account_address_label.config(text="Address: " + account_details['address'])
    account_quota_label.config(text="Quota: " + str(account_details['quota']))
    account_created_at_label.config(
        text="Created At: " + account_details['createdAt'])

    # Log in to get the JWT token
    token_url = "https://api.mail.tm/token"
    login_data = {
        "address": account_details['address'],
        "password": password
    }
    token_response = requests.post(
        token_url, json=login_data, timeout=REQUEST_TIMEOUT
    )
    token_response.raise_for_status()
    token_details = token_response.json()

    jwt_token = token_details['token']

    # Use the JWT token to fetch messages
    messages_url = "https://api.mail.tm/messages"
    headers = {
        "Authorization": f"Bearer {jwt_token}"
    }
    messages_response = requests.get(
        messages_url, headers=headers, timeout=REQUEST_TIMEOUT
    )
    messages_response.raise_for_status()
    messages_data = messages_response.json()

    # print messages_data in messages_result_text
    messages_result_text.delete("1.0", tk.END)
    messages_result_text.insert(tk.END, str(messages_data))

# Refresh Messages Function


def refresh_messages():
    # Use global variables defined in `generate_temp_mail`
    global headers, messages_url, messages_result_text
    messages_response = requests.get(
        messages_url, headers=headers, timeout=REQUEST_TIMEOUT
    )
    messages_response.raise_for_status()
    messages_data = messages_response.json()

    # Clear existing text in the result box
    messages_result_text.delete("1.0", tk.END)

    # Loop through each message and format its relevant data
    for message in messages_data['hydra:member']:
        message_info = (
            f"id: {message['id']}\n"
            f"from: {message['from']['address']}\n"
            f"subject: {message['subject']}\n"
            f"intro: {message['intro']}\n"
            f"seen: {message['seen']}\n"
            f"createdAt: {message['createdAt']}\n"
            "------------------------\n"
        )
        messages_result_text.insert(tk.END, message_info)


# Function to handle about SheeKryptor
def about_sheekryptor():
    messagebox.showinfo(
        "About SheeKryptor",
        f"{APP_NAME} protects files with authenticated encryption.\n\n"
        f"Version: {APP_VERSION}\n\nAuthor: Ahmed Sheeko\n\n"
        "GitHub: github.com/Sheekovic/SheeKryptor",
    )


"""
################## Main GUI ##################
this is the main GUI
you can add widgets here
"""
root = ThemedTk(theme=settings_theme)
root.title(f"{APP_NAME} {APP_VERSION}")
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
window_width = max(800, min(1280, screen_width - 80))
window_height = max(640, min(860, screen_height - 80))
window_x = max(0, (screen_width - window_width) // 2)
window_y = max(0, (screen_height - window_height) // 2)
root.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")
root.minsize(min(960, window_width), min(680, window_height))
root.configure(background="#07111f")
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)

try:
    root.iconbitmap("assets/SheeKryptor.ico")
except tk.TclError:
    pass

fontStyle = settings_font_style if settings_font_style else "Segoe UI"
fontSize = int(settings_font_size) if str(settings_font_size).isdigit() else 11
headerFontSize = fontSize + 10

black = "#07111f"
white = "#edf5ff"
green = "#43e6b1"
red = "#ff758b"
gray = "#0e1c2d"
muted = "#94a9bf"
input_background = "#091524"
border = "#263a50"

style = ttk.Style(root)
style.configure(
    "TNotebook", background=black, borderwidth=0, tabmargins=(0, 8, 0, 0)
)
style.configure(
    "TNotebook.Tab",
    background=gray,
    foreground=muted,
    borderwidth=0,
    padding=(10, 10),
    font=(fontStyle, 9, "bold"),
)
style.map(
    "TNotebook.Tab",
    background=[("selected", "#153046"), ("active", "#13283b")],
    foreground=[("selected", green), ("active", white)],
)
style.configure(
    "TFrame", background=gray, relief="flat"
)
style.configure(
    "TLabel", background=gray, foreground=white, font=(fontStyle, fontSize)
)
style.configure(
    "TEntry",
    fieldbackground=input_background,
    foreground=white,
    bordercolor=border,
    lightcolor=border,
    darkcolor=border,
    padding=(10, 8),
    font=(fontStyle, fontSize),
)
style.configure(
    "TCombobox",
    fieldbackground=input_background,
    background=input_background,
    foreground=white,
    arrowcolor=green,
    padding=(8, 6),
    font=(fontStyle, fontSize),
)
style.map(
    "TCombobox",
    fieldbackground=[("readonly", input_background)],
    foreground=[("readonly", white)],
)
style.configure(
    "TButton",
    background="#153047",
    foreground=white,
    borderwidth=0,
    padding=(14, 9),
    font=(fontStyle, max(fontSize - 1, 9), "bold"),
)
style.map(
    "TButton",
    background=[("pressed", "#1aa77e"), ("active", "#1c425b")],
    foreground=[("pressed", "#03251c"), ("active", white)],
)
style.configure(
    "Accent.TButton",
    background=green,
    foreground="#03251c",
    padding=(18, 11),
    font=(fontStyle, max(fontSize - 1, 9), "bold"),
)
style.map(
    "Accent.TButton",
    background=[("pressed", "#25bd91"), ("active", "#65efc1")],
    foreground=[("pressed", "#03251c"), ("active", "#03251c")],
)
style.configure("TCheckbutton", background=gray, foreground=white)
style.configure("TRadiobutton", background=gray, foreground=white)
style.configure("TScrollbar", background="#183149", troughcolor=gray)
style.configure(
    "Treeview",
    background=input_background,
    fieldbackground=input_background,
    foreground=white,
    rowheight=30,
)
style.configure(
    "Treeview.Heading",
    background="#153047",
    foreground=white,
    font=(fontStyle, max(fontSize - 1, 9), "bold"),
)
style.map("Treeview", background=[("selected", "#1b5b64")])
style.configure("TProgressbar", background=green, troughcolor=input_background)

app_header = tk.Frame(root, background=black)
app_header.grid(row=0, column=0, sticky="ew", padx=28, pady=(20, 12))
app_header.grid_columnconfigure(0, weight=1)
tk.Label(
    app_header,
    text=APP_NAME,
    background=black,
    foreground=white,
    font=(fontStyle, 22, "bold"),
).grid(row=0, column=0, sticky="w")
tk.Label(
    app_header,
    text="Private tools. Local processing. Authenticated encryption.",
    background=black,
    foreground=muted,
    font=(fontStyle, 10),
).grid(row=1, column=0, sticky="w", pady=(3, 0))
tk.Label(
    app_header,
    text=f"v{APP_VERSION}  |  AES-256-GCM",
    background=black,
    foreground=green,
    font=(fontStyle, 9, "bold"),
).grid(row=0, column=1, rowspan=2, sticky="e")

# Create Tabs for Decryptor and Encryptor
tab_control = ttk.Notebook(root, style="TNotebook")

# Decryptor tab
decryptor_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(decryptor_tab, text="Decrypt", padding=10)

# Encryptor tab
encryptor_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(encryptor_tab, text="Encrypt", padding=10)

# PWD Generator tab
pwd_generator_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(pwd_generator_tab, text="Passwords", padding=10)

# Add the API Testing Tab to the Notebook
api_testing_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(api_testing_tab, text="API", padding=10)

# Add 2FA Tool Tab to the Notebook
two_factor_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(two_factor_tab, text="Authenticator", padding=10)

# SquashIt tab
squashit_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(squashit_tab, text="Archive", padding=10)

# ConvertX tab
convertx_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(convertx_tab, text="Convert", padding=10)

# Temp Mail tab
temp_mail_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(temp_mail_tab, text="Mail", padding=10)

# Settings tab
settings_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(settings_tab, text="Settings", padding=10)

# About tab
about_tab = ttk.Frame(tab_control, style="TFrame")
tab_control.add(about_tab, text="About", padding=10)

# Center the tabs in the window
tab_control.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 24))

"""
#################### Decryptor Tab ####################
This tab provides the interface for decrypting files. 
Users can input the file to decrypt, provide the password, and initiate the decryption process.
The layout ensures all widgets are centered and evenly spaced.
"""
# Configure columns and rows for alignment
decryptor_tab.grid_columnconfigure(0, weight=1)
decryptor_tab.grid_columnconfigure(1, weight=1)
decryptor_tab.grid_columnconfigure(2, weight=1)
for i in range(6):  # Ensure all rows align uniformly
    decryptor_tab.grid_rowconfigure(i, weight=1)

# Decryptor Tab Input Fields and Buttons
decryptor_label = ttk.Label(decryptor_tab, text="Decryptor", style="TLabel")
decryptor_label.grid(row=0, column=0, columnspan=3, pady=10)

# Description for decryptor tool
decryptor_description = ttk.Label(
    decryptor_tab,
    text=(
        "Use this tool to decrypt files. Select the file, enter the correct password, "
        "and click the 'Decrypt' button to retrieve the original content."
    ),
    style="TLabel",
    wraplength=600,  # Ensure the text wraps for readability
    justify="center",
)
decryptor_description.grid(row=1, column=0, columnspan=3, padx=20, pady=10)

ttk.Label(decryptor_tab, text="Input File:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10, sticky="e")

ttk.Button(decryptor_tab, text="Browse", command=browse_input_file_decrypt,
           style="TButton").grid(row=2, column=2, padx=10, pady=10)

# Ensure we are not using a custom style for the input field and check behavior without it
decryptor_input_file_entry = ttk.Entry(decryptor_tab, width=70, style="TEntry")
decryptor_input_file_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

ttk.Label(decryptor_tab, text="Password:", style="TLabel").grid(
    row=3, column=0, padx=10, pady=10, sticky="e")
decryptor_password_entry = ttk.Entry(
    decryptor_tab, width=70, style="TEntry", show="•"
)
decryptor_password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

ttk.Button(decryptor_tab, text="Decrypt", command=start_decryption,
           style="Accent.TButton").grid(row=4, column=0, columnspan=3, pady=20)

# Log Text Area
decryptor_log = tk.Text(decryptor_tab, width=80, height=10, wrap="word",
                        state="normal", background=input_background,
                        foreground=white, insertbackground=green,
                        selectbackground="#1b5b64", relief="flat",
                        padx=12, pady=12, font=(fontStyle, 10))
decryptor_log.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

"""
#################### Encryptor Tab ####################
This tab provides the interface for encrypting files.
Users can input the file to encrypt, provide the password, and initiate the encryption process.
The layout ensures all widgets are centered and evenly spaced.
"""
# Configure columns and rows for alignment
encryptor_tab.grid_columnconfigure(0, weight=1)
encryptor_tab.grid_columnconfigure(1, weight=1)
encryptor_tab.grid_columnconfigure(2, weight=1)
for i in range(6):  # Ensure all rows align uniformly
    encryptor_tab.grid_rowconfigure(i, weight=1)

# Encryptor Tab Title
ttk.Label(encryptor_tab, text="Encryptor", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Description for the Encryptor tool
ttk.Label(
    encryptor_tab,
    text=(
        "The Encryptor tool allows you to securely encrypt files with a password. "
        "Select the file you wish to encrypt, enter a strong password, and click 'Encrypt' "
        "to generate an encrypted file."
    ),
    wraplength=600,  # Adjust width for better readability
    style="TLabel"
).grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Encryptor Tab Input Fields and Buttons
ttk.Label(encryptor_tab, text="Input File:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10, sticky="e")
encryptor_input_file_entry = ttk.Entry(encryptor_tab, width=70, style="TEntry")
encryptor_input_file_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
ttk.Button(encryptor_tab, text="Browse", command=browse_input_file_encrypt,
           style="TButton").grid(row=2, column=2, padx=10, pady=10)

ttk.Label(encryptor_tab, text="Password:", style="TLabel").grid(
    row=3, column=0, padx=10, pady=10, sticky="e")
encryptor_password_entry = ttk.Entry(
    encryptor_tab, width=70, style="TEntry", show="•"
)
encryptor_password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

ttk.Button(encryptor_tab, text="Encrypt", command=start_encryption,
           style="Accent.TButton").grid(row=4, column=0, columnspan=3, pady=20)

# log output text widget to display logs
log_output_text = tk.Text(encryptor_tab, width=80, height=10,
                          wrap="word", background=input_background,
                          foreground=white, insertbackground=green,
                          selectbackground="#1b5b64", relief="flat",
                          padx=12, pady=12, font=(fontStyle, 10))
log_output_text.grid(row=5, column=0, columnspan=3, padx=10, pady=10)
log_output_text.config(state='normal')
log_output_text.insert('end', 'Encryption Log:\n')

"""
#################### PWD Generator Tab ####################
This tab provides the interface for generating strong passwords.
Users can input the desired password length and click the "Generate Password" button.
The layout ensures all widgets are centered and evenly spaced.
"""
# Configure columns and rows for alignment
pwd_generator_tab.grid_columnconfigure(0, weight=1)
pwd_generator_tab.grid_columnconfigure(1, weight=1)

for i in range(10):  # Add weights for all rows
    pwd_generator_tab.grid_rowconfigure(i, weight=1)

# Strong Password Generator Section
ttk.Label(pwd_generator_tab, text="Strong Password Generator",
          style="TLabel").grid(row=0, column=0, columnspan=2, pady=20)

# Description for the Strong Password Generator tool
ttk.Label(
    pwd_generator_tab,
    text=(
        "The Strong Password Generator helps you create secure passwords of a specified length. "
        "Simply enter the desired password length and click 'Generate Password' to produce a random, "
        "strong password."
    ),
    wraplength=600,  # Adjust width for readability
    style="TLabel"
).grid(row=1, column=0, columnspan=2, padx=10, pady=10)

# Password length input field
ttk.Label(pwd_generator_tab, text="Password Length:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10, sticky="e")
password_length_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
password_length_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# Button to generate password
ttk.Button(pwd_generator_tab, text="Generate Password", command=create_password,
           style="TButton").grid(row=3, column=0, columnspan=2, pady=20)

# Password entry field
ttk.Label(pwd_generator_tab, text="Generated Password:", style="TLabel").grid(
    row=4, column=0, padx=10, pady=10, sticky="e")
password_entry = ttk.Entry(pwd_generator_tab, width=40, style="TEntry")
password_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Personalized Password Generator Section
ttk.Label(pwd_generator_tab, text="Personalized Password Generator",
          style="TLabel").grid(row=5, column=0, columnspan=2, pady=20)

# Description for the Personalized Password Generator tool
ttk.Label(
    pwd_generator_tab,
    text=(
        "The Personalized Password Generator creates passwords based on user-specific details such as "
        "name, date of birth, and preferred password length. This can help generate memorable yet secure passwords."
    ),
    wraplength=600,  # Adjust width for readability
    style="TLabel"
).grid(row=6, column=0, columnspan=2, padx=10, pady=10)

# Name input field
ttk.Label(pwd_generator_tab, text="Name:", style="TLabel").grid(
    row=7, column=0, padx=10, pady=10, sticky="e")
name_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
name_entry.grid(row=7, column=1, padx=10, pady=10, sticky="w")

# Date of Birth input field
ttk.Label(pwd_generator_tab, text="Date of Birth:", style="TLabel").grid(
    row=8, column=0, padx=10, pady=10, sticky="e")
dob_entry = ttk.Entry(pwd_generator_tab, width=20, style="TEntry")
dob_entry.grid(row=8, column=1, padx=10, pady=10, sticky="w")

# Password Length input field
ttk.Label(pwd_generator_tab, text="Password Length:", style="TLabel").grid(
    row=9, column=0, padx=10, pady=10, sticky="e")
personal_password_length_entry = ttk.Entry(
    pwd_generator_tab, width=20, style="TEntry")
personal_password_length_entry.grid(
    row=9, column=1, padx=10, pady=10, sticky="w")

# Button to generate personalized password
ttk.Button(pwd_generator_tab, text="Generate Password", command=generate_personalized_password,
           style="TButton").grid(row=10, column=0, columnspan=2, pady=20)

# Password entry field
ttk.Label(pwd_generator_tab, text="Generated Password:", style="TLabel").grid(
    row=11, column=0, padx=10, pady=10, sticky="e")
personal_password_entry = ttk.Entry(
    pwd_generator_tab, width=40, style="TEntry")
personal_password_entry.grid(row=11, column=1, padx=10, pady=10, sticky="w")

"""
#################### API Test Tab ####################
this tab is for api testing
"""
# Configure columns and rows for centering
api_testing_tab.grid_columnconfigure(0, weight=1)
for i in range(12):  # Ensure all rows align uniformly
    api_testing_tab.grid_rowconfigure(i, weight=1)

# API Testing Tab Title
ttk.Label(api_testing_tab, text="API Testing", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# API URL Entry
ttk.Label(api_testing_tab, text="API URL:", style="TLabel").grid(
    row=1, column=0, padx=10, pady=10, sticky="w")  # Align label to the right
api_url_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
api_url_entry.grid(row=1, column=1, padx=10, pady=10, sticky="e")

# API Request Type (GET, POST, PUT, DELETE)
ttk.Label(api_testing_tab, text="Request Type:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10, sticky="w")
request_type_combobox = ttk.Combobox(api_testing_tab, values=[
                                     "GET", "POST", "PUT", "DELETE"], style="TCombobox", state="readonly", justify="center")
request_type_combobox.set("GET")  # Set default value
request_type_combobox.grid(row=2, column=1, padx=10, pady=10)

# Headers input (JSON format example)
ttk.Label(api_testing_tab, text="Headers (JSON format):", style="TLabel").grid(
    row=3, column=0, padx=10, pady=10, sticky="w")
headers_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
headers_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# Authentication Token input
ttk.Label(api_testing_tab, text="Auth Token:", style="TLabel").grid(
    row=4, column=0, padx=10, pady=10, sticky="w")
auth_token_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
auth_token_entry.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Request Body Entry (For POST/PUT requests)
ttk.Label(api_testing_tab, text="Request Body (JSON format):",
          style="TLabel").grid(row=5, column=0, padx=10, pady=10, sticky="w")
request_body_entry = ttk.Entry(api_testing_tab, width=70, style="TEntry")
request_body_entry.grid(row=5, column=1, padx=10, pady=10, sticky="w")

# Response Viewer (Text area)
response_text = tk.Text(api_testing_tab, width=80, height=15,
                        wrap="word", background=gray, foreground=green)
response_text.grid(row=7, column=0, columnspan=3, padx=10, pady=10)

# Send Request Button
ttk.Button(api_testing_tab, text="Test API", command=send_api_request,
           style="TButton").grid(row=6, column=0, pady=10, columnspan=3)

# Save Results Button
ttk.Button(api_testing_tab, text="Save Results", command=save_results,
           style="TButton").grid(row=8, column=0, pady=10, columnspan=3)

"""
#################### 2FA Tool Tab ####################
this tab is for 2FA tool functionality
"""
two_factor_tab.grid_columnconfigure(0, weight=1)
for i in range(12):  # Ensure all rows align uniformly
    two_factor_tab.grid_rowconfigure(i, weight=1)


# Input Section
frame = ttk.Frame(two_factor_tab)
frame.pack(pady=10)

time_based_var = tk.IntVar()

ttk.Label(frame, text="Provider:").grid(row=0, column=0, padx=5, pady=5)
provider_entry = ttk.Entry(frame)
provider_entry  .grid(row=0, column=1, padx=5, pady=5)

ttk.Label(frame, text="Username/Email:").grid(row=1, column=0, padx=5, pady=5)
username_entry = ttk.Entry(frame)
username_entry.grid(row=1, column=1, padx=5, pady=5)

ttk.Label(frame, text="2FA Key:").grid(row=2, column=0, padx=5, pady=5)
key_entry = ttk.Entry(frame, show="•")
key_entry.grid(row=2, column=1, padx=5, pady=5)

time_based_checkbox = ttk.Checkbutton(
    frame, text="TOTP (30-second codes)", variable=time_based_var)
# Set the default value to True
time_based_var.set(True)
time_based_checkbox.grid(row=3, column=1, pady=5)

add_button = ttk.Button(frame, text="Add Account", command=add_account)
add_button.grid(row=4, column=0, columnspan=2, pady=10)

# Accounts Table
columns = ("id", "Provider", "Account", "OTP")
accounts_table = ttk.Treeview(frame, columns=columns, show="headings")
accounts_table.heading("id", text="ID")
accounts_table.heading("Provider", text="Provider")
accounts_table.heading("Account", text="Account")
accounts_table.heading("OTP", text="OTP")
accounts_table.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

# make the table scrollable
scrollbar = ttk.Scrollbar(frame, orient="vertical",
                          command=accounts_table.yview)
scrollbar.grid(row=5, column=2, sticky="ns")
accounts_table.configure(yscrollcommand=scrollbar.set)

# combo box for accounts to choose to delete
account_combobox = ttk.Combobox(
    frame, values=[], state="readonly", justify="center")
account_combobox.set(1)
account_combobox.grid(row=6, column=0, padx=10, pady=10, sticky="nsew")
# Delete Button
delete_button = ttk.Button(
    frame, text="Delete Account", command=delete_account)
delete_button.grid(row=6, column=1, columnspan=2, pady=10)

# Start OTP Update
refresh_accounts()
update_otps()


"""
#################### SquashIt Tab ####################
SquashIt creates portable ZIP archives with safe extraction checks.
"""
squashit_tab.grid_columnconfigure(0, weight=1)
squashit_tab.grid_columnconfigure(1, weight=1)
squashit_tab.grid_columnconfigure(2, weight=1)
for i in range(12):  # Ensure all rows align uniformly
    squashit_tab.grid_rowconfigure(i, weight=1)

# SquashIt Tab Title
ttk.Label(squashit_tab, text="SquashIt", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Description for the SquashIt tool
ttk.Label(
    squashit_tab,
    text=(
        "Create a standard ZIP archive that works across operating systems. "
        "Select one or more files, choose the Deflate compression level, and create the archive."
    ),
    wraplength=600,  # Adjust width for better readability
    style="TLabel"
).grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Compression Level ComboBox
ttk.Label(squashit_tab, text="Compression Level (0 to 9)").grid(
    row=2, column=0, padx=10, pady=10)
compression_level_combobox = ttk.Combobox(
    squashit_tab, values=[str(i) for i in range(10)], state="readonly", width=5
)
compression_level_combobox.set(9)  # Default value
compression_level_combobox.grid(row=2, column=1, padx=10, pady=10)

# Input Files Selection
ttk.Label(squashit_tab, text="Select Files:").grid(
    row=3, column=0, padx=10, pady=10)
input_files_entry = ttk.Entry(squashit_tab, width=40)
input_files_entry.grid(row=3, column=1, padx=10, pady=10)
ttk.Button(squashit_tab, text="Browse", command=lambda: browse_file(
    input_files_entry)).grid(row=3, column=2, padx=10, pady=10)

# Output File Selection
ttk.Label(squashit_tab, text="Output File:").grid(
    row=4, column=0, padx=10, pady=10)
output_file_entry = ttk.Entry(squashit_tab, width=40)
output_file_entry.grid(row=4, column=1, padx=10, pady=10)
ttk.Button(squashit_tab, text="Browse", command=lambda: browse_output(
    output_file_entry, 'SquashIt')).grid(row=4, column=2, padx=10, pady=10)

# Compression Button
ttk.Button(squashit_tab, text="SquashIT", command=lambda: squashit(input_files_entry.get().split(', '), output_file_entry.get(
), int(compression_level_combobox.get())), style="Accent.TButton").grid(row=5, column=0, columnspan=3, pady=20)

# Result Label
squashit_result_label = ttk.Label(
    squashit_tab, text="", foreground="green", font=(fontStyle, 8))
squashit_result_label.grid(row=8, column=0, columnspan=3, padx=10, pady=10)

# input Label for the decompression tool
ttk.Label(squashit_tab, text="Input Files:").grid(
    row=9, column=0, padx=10, pady=10)
unsquashit_input_files_entry = ttk.Entry(squashit_tab, width=40)
unsquashit_input_files_entry.grid(row=9, column=1, padx=10, pady=10)
ttk.Button(squashit_tab, text="Browse", command=lambda: browse_file(
    unsquashit_input_files_entry)).grid(row=9, column=2, padx=10, pady=10)

# Decompression Button (updated to pass the correct arguments)
ttk.Button(squashit_tab, text="UnSquashIT", command=lambda: unsquashit(
    unsquashit_input_files_entry.get().split(', '), ''), style="Accent.TButton").grid(row=10, column=0, columnspan=3, pady=20)

# result Label
unsquashit_result_label = ttk.Label(
    squashit_tab, text="", foreground="green", font=(fontStyle, 8))
unsquashit_result_label.grid(row=11, column=0, columnspan=3, padx=10, pady=10)


"""
#################### ConvertX Tab ####################
"""
# Conversion tab layout
convertx_tab.grid_columnconfigure(0, weight=1)
convertx_tab.grid_columnconfigure(1, weight=1)
convertx_tab.grid_columnconfigure(2, weight=1)

for i in range(10):  # Ensure all rows align uniformly
    convertx_tab.grid_rowconfigure(i, weight=1)

# ConvertX Tab Title
ttk.Label(convertx_tab, text="ConvertX", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Description for the ConvertX tool
ttk.Label(convertx_tab, text="ConvertX is a powerful tool for converting between various formats "
                             "including image to base64, base64 to image, text encoding conversions, "
                             "and much more. Choose your conversion type and proceed with ease.",
          wraplength=600,  # Adjust width for better readability
          style="TLabel").grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Conversion Type ComboBox
ttk.Label(convertx_tab, text="Conversion Type").grid(
    row=2, column=0, padx=10, pady=10)
conversion_type_combobox = ttk.Combobox(
    convertx_tab, values=["Image to Base64", "Base64 to Image", "Text Encoding", "Base64 to Text"], state="readonly", width=15
)
conversion_type_combobox.set("Image to Base64")  # Default value
conversion_type_combobox.grid(row=2, column=1, padx=10, pady=10)

# Input Files Selection
ttk.Label(convertx_tab, text="Select Files:").grid(
    row=3, column=0, padx=10, pady=10)
input_files_entry = ttk.Entry(convertx_tab, width=40)
input_files_entry.grid(row=3, column=1, padx=10, pady=10)

ttk.Button(convertx_tab, text="Browse", command=lambda: browse_file(
    input_files_entry)).grid(row=3, column=2, padx=10, pady=10)

# Conversion Button
ttk.Button(convertx_tab, text="Convert", command=lambda: convertx(
    input_files_entry.get().split(', '), conversion_type_combobox.get())).grid(row=5, column=0, columnspan=3, pady=20)

# Result Label
convertx_result_label = ttk.Label(
    convertx_tab, text="", foreground="green", font=("Arial", 8))
convertx_result_label.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

# Result text box area for ConvertX
convertx_result_text = tk.Text(
    convertx_tab, height=15, width=80, wrap="word", background=gray, foreground=green)
convertx_result_text.grid(row=6, column=0, columnspan=3, padx=10, pady=10)


"""
#################### Temp Mail Tab ####################
Temp Mail to Generate a Temporary Email Address
"""

# configure columns and rows for alignment
temp_mail_tab.grid_columnconfigure(0, weight=1)
temp_mail_tab.grid_columnconfigure(1, weight=1)
temp_mail_tab.grid_columnconfigure(2, weight=1)
for i in range(10):  # Ensure all rows align uniformly
    temp_mail_tab.grid_rowconfigure(i, weight=1)

# Temp Mail Tab Title
ttk.Label(temp_mail_tab, text="Temp Mail", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Name Label
ttk.Label(temp_mail_tab, text="Name:", style="TLabel").grid(
    row=1, column=0, padx=10, pady=10)

# Name Entry
name_entry = ttk.Entry(temp_mail_tab, width=40)
name_entry.grid(row=1, column=1, padx=10, pady=10)

# Password Label
ttk.Label(temp_mail_tab, text="Password:", style="TLabel").grid(
    row=2, column=0, padx=10, pady=10)

# Password Entry
password_entry = ttk.Entry(temp_mail_tab, show="*", width=40)
password_entry.grid(row=2, column=1, padx=10, pady=10)

# Generate Temp Mail Button
ttk.Button(temp_mail_tab, text="Generate Temp Mail", command=generate_temp_mail).grid(
    row=3, column=0, columnspan=3, pady=20)

# Account ID Label
account_id_label = ttk.Label(temp_mail_tab, text="", style="TLabel")
account_id_label.grid(row=4, column=0, padx=10, pady=10, columnspan=3)

# Account Address Label
account_address_label = ttk.Label(temp_mail_tab, text="", style="TLabel")
account_address_label.grid(row=5, column=0, padx=10, pady=10, columnspan=3)

# Account Quota Label
account_quota_label = ttk.Label(temp_mail_tab, text="", style="TLabel")
account_quota_label.grid(row=6, column=0, padx=10, pady=10, columnspan=3)

# Account Created At Label
account_created_at_label = ttk.Label(temp_mail_tab, text="", style="TLabel")
account_created_at_label.grid(row=7, column=0, padx=10, pady=10, columnspan=3)

# Result text box area for Messages
messages_result_text = tk.Text(
    temp_mail_tab, height=15, width=80, wrap="word", background=gray, foreground=green)
messages_result_text.grid(row=8, column=0, columnspan=3, padx=10, pady=10)

# Refresh Button
ttk.Button(temp_mail_tab, text="Refresh", command=refresh_messages).grid(
    row=9, column=0, columnspan=3, pady=20)


"""
#################### Settings Tab ####################
settings_tab is a tab that allows users to configure various settings, such as theme, font style, and font size.
"""

# Configure columns and rows for alignment
settings_tab.grid_columnconfigure(0, weight=1)
settings_tab.grid_columnconfigure(1, weight=1)
settings_tab.grid_columnconfigure(2, weight=1)
for i in range(10):  # Ensure all rows align uniformly
    settings_tab.grid_rowconfigure(i, weight=1)

# Settings Tab Title
ttk.Label(settings_tab, text="Settings", style="TLabel").grid(
    row=0, column=0, columnspan=3, pady=20)

# Title Label
ttk.Label(settings_tab, text="Theme Control",
          style="TLabel").grid(row=1, column=0, pady=20)

# List available themes in the combobox
available_themes = root.get_themes()
theme_combobox = ttk.Combobox(
    settings_tab, values=available_themes, style="TCombobox", state="readonly", justify="center"
)
theme_combobox.set(settings_theme)  # Set the current theme as default
theme_combobox.grid(row=1, column=1, padx=10, pady=10)

# Label for font style
ttk.Label(settings_tab, text="Change Font Style", style="TLabel").grid(
    row=2, column=0, pady=20)

# List available font styles in the combobox
# Get and sort available font families
available_font_styles = sorted(tkFont.families())
font_style_combobox = ttk.Combobox(
    settings_tab, values=available_font_styles, style="TCombobox", state="readonly", justify="center"
)
# Set the current font style as default
font_style_combobox.set(settings_font_style)
font_style_combobox.grid(row=2, column=1, padx=10, pady=10)

# Label for font size
ttk.Label(settings_tab, text="Change Font Size", style="TLabel").grid(
    row=3, column=0, pady=20)


# List available font sizes in the combobox
available_font_sizes = [8, 10, 12, 14, 16, 18,
                        20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40]
font_size_combobox = ttk.Combobox(
    settings_tab, values=available_font_sizes, style="TCombobox", state="readonly", justify="center"
)
# Set the current font size as default
font_size_combobox.set(settings_font_size)
font_size_combobox.grid(row=3, column=1, padx=10, pady=10)

# Button to apply font options
apply_font_size_button = ttk.Button(
    settings_tab, text="Apply Settings", command=update_settings, style="TButton")
apply_font_size_button.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

# Exit Button
ttk.Label(
    settings_tab,
    text="To close the application",
    wraplength=600,  # Adjust for better readability
    style="TLabel"
).grid(row=5, column=0, padx=10, pady=10)

exit_button = ttk.Button(settings_tab, text="Exit",
                         command=root.destroy, style="TButton")
exit_button.grid(row=5, column=1, padx=10, pady=10)

"""
#################### About Tab ####################
About Tab is a tab that provides information about the application and its features.
"""

about_tab.grid_columnconfigure(0, weight=1)
about_tab.grid_columnconfigure(1, weight=1)

for i in range(4):  # Add weights for all rows
    about_tab.grid_rowconfigure(i, weight=1)


# SheeKryptor
ttk.Label(about_tab, text="SheeKryptor", style="TLabel").grid(
    row=0, column=0, columnspan=2, pady=20)

# App Description
app_description = (
    "is a powerful and user-friendly tool for file encryption and decryption and MORE.\n"
    "With an intuitive interface and robust functionality, it ensures your data remains secure."
)
ttk.Label(about_tab, text=app_description, wraplength=600, anchor="center", justify="center", style="TLabel").grid(
    row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew"
)

# Version and Features
version_info = (
    f"Version: {APP_VERSION}\n"
    "Features:\n"
    "- Secure File Encryption & Decryption\n"
    "- Strong Password Generator\n"
    "- API Testing & Development\n"
    "- 2FA Tool - Two Factor Authentication\n"
    "- SquashIt - File Compression\n"
    "- Support for Multiple Themes\n"
    "- Intuitive User Interface\n"
    "- More Coming Soon..."
)
ttk.Label(about_tab, text=version_info, anchor="center", justify="center", style="TLabel").grid(
    row=2, column=0, columnspan=2, padx=20, pady=10, sticky="nsew"
)

# Credits
credits = (
    "Developed by: Sheekovic\n"
    "GitHub: @Sheekovic\n"
    "Facebook: /Sheekovic\n"
    "\nThank you for using SheeKryptor!"
)
ttk.Label(about_tab, text=credits, anchor="center", justify="center", style="TLabel").grid(
    row=3, column=0, columnspan=2, padx=20, pady=10, sticky="nsew"
)

tab_control.select(decryptor_tab)
root.mainloop()
