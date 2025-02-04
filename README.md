# SheeKryptor!!

SheeKryptor is a secure file encryption and decryption tool designed for ease of use. It allows users to encrypt and decrypt files with strong AES encryption. The tool also includes password generation and personalization features for enhanced security.

## Features

- **File Encryption**: Encrypt files securely with AES (CBC mode) using a user-defined password.
- **File Decryption**: Decrypt encrypted files by providing the correct password.
- **Password Generator**: Generate strong passwords with the option to create personalized passwords based on your name and date of birth.
- **API Testing**: Test any API endpoints with the SheeKryptor API , which supports GET, POST, PUT, and DELETE requests.
- **2FA Tool**: Securely manage and generate OTP codes for Two-Factor Authentication (TOTP) accounts.
- **SquashIT**: Compress and decompress files using zlib, gzip, and tar.zlib.
- **ConvertX**: Convert between different file formats, including image to Base64, Base64 to image, text encoding, and Base64 to text.
- **Temp Mail**: Generate and manage temporary emails for testing purposes.
- **User-Friendly GUI**: Simple and intuitive graphical interface built using Tkinter.
- **Customizable Settings**: Change the theme and font style/size for a personalized experience.
- **Cross-Platform**: Works on Windows, macOS, and Linux.

## Installation

1. **Clone this repository**:
   ```bash
   git clone https://github.com/sheekovic/SheeKryptor.git
   cd SheeKryptor
   ```
   or from GitHub CLI
   ```bash
   gh repo clone Sheekovic/SheeKryptor
   cd SheeKryptor
   ```

2. **Install the required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the program**:
   ```bash
   python sheekryptor.py
   ```

4. **If you're lazy or this thing is new to you**
-- Run `EasySetup(RunFromHere).bat` file, and you're good to go


## Requirements

- Python 3.10 or later
- `cryptography` package
- `tkinter` (for GUI)
- `ttkthemes` (for theme styling)
- `pyotp` package
- `requests` package
- `pillow` package

## Usage

### Encrypt a File
1. Go to the "Encryptor" tab.
2. Select the file you wish to encrypt by clicking "Browse".
3. Enter a strong password.
4. Click the "Encrypt" button to generate the encrypted file.
5. The encrypted file will be saved in the `encrypted_files` folder with `_encrypted` appended to the filename.
6. Added Log Box for viewing the encryption process logs.

### Decrypt a File
1. Go to the "Decryptor" tab.
2. Select the encrypted file by clicking "Browse".
3. Enter the password used for encryption.
4. Click the "Decrypt" button to retrieve the original file.
5. The decrypted file will be saved in the `decrypted_files` folder with `_decrypted` appended to the filename.
6. Added Log Box for viewing the decryption process logs.

### Password Generator
1. Go to the "PWD Generator" tab.
2. Choose the length for the password you want to generate.
3. Click "Generate" to create a random strong password.

### Personalized Password
1. Go to the "PWD Generator" tab.
2. Enter your name and date of birth.
3. Choose the password length.
4. Click "Generate" to create a personalized password based on your details.

### API Testing
1. Go to the "API Testing" tab.
2. Enter the API endpoint URL.
3. Select the HTTP method (GET, POST, PUT, DELETE).
4. Enter any required parameters.
5. click "Test API" to send the request and view the response.
6. Save Results to a text file by clicking "Save Results".

### 2FA Tool - Two Factor Authentication
1. Go to the "2FA Tool" tab - This section allows you to manage your Two-Factor Authentication (2FA) accounts.
2. Enter the name of the provider (e.g., Google, Facebook) in the "Provider" field.
3. Provide the username or email associated with your 2FA account in the "Username/Email" field.
4. Enter your secret 2FA key in the "2FA Key" field. This key is typically provided by the service when setting up 2FA.
5. If your 2FA method uses time-based one-time passwords (TOTP), check the "Time Based" checkbox (optional).
6. Add Your Account Click "Add Account" button to save the 2FA details for this account to the database.
7. View Accounts All added accounts will be listed in the table below, showing the provider name, username/email, and the generated OTP (One-Time Password) for that account.
8. Delete an Account.
   - To delete an account, select the account from the "Select Account" dropdown.
   - Click "Delete Account" to remove it from the database.
9. OTP Refresh for each account will be refreshed every second to show the current code. The table will display the updated OTP in real-time.

### SquashIT Tool - File Compression
1. Go to the "SquashIT" tab.
2. Select the file you want to compress by clicking "Browse".
3. Choose the compression method (zlib, gzip, tar.zlib).
4. Set the compression level (0-9).
5. Click "Compress" to start the compression process.

### UnSquashIT Tool - File Decompression
1. Go to the "SquashIT" tab.
2. Select the compressed file by clicking "Browse".
3. Click "UnSquashIT" to decompress the file.

### ConvertX Tool - File Conversion
1. Go to the "ConvertX" tab.
2. Select the file you want to convert by clicking "Browse".
3. Choose the conversion type (image to Base64, Base64 to image, text encoding, Base64 to text).
4. Click "Convert" to start the conversion process.
5. The converted file will be saved in the same directory as the original file.

### Temp Mail Tool - Generate and Manage Temporary Emails
1. Go to the "Temp Mail" tab.
2. Enter Name and Password.
3. Click "Generate" to generate a temporary email address.
4. Refresh button to refresh messages.

## Themes and Font Customization
1. Go to the "Settings" tab.
2. Change the theme from the dropdown list.
3. Customize the font style and size to your preference.
4. Settings will be saved and applied on the next launch.

## About

SheeKryptor is a simple but powerful tool for securely encrypting and decrypting files. It aims to provide a safe and easy-to-use solution for managing sensitive data.

- **Version**: v2.4.5
- **Author**: Ahmeed Sheeko
- **Contact**: sheekovic@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
