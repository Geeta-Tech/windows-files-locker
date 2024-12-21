import sys
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet,InvalidToken
import ctypes

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Restart the script with administrative privileges if not already running as admin."""
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def generate_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        print("Key file generated: key.key")
    else:
        print("Key already exists: key.key")

def load_key():
    if os.path.exists("key.key"):
        return open("key.key", "rb").read()
    else:
        messagebox.showerror("Error", "Key file not found!")
        return None
    

def encrypt_files_thread(file_paths, key, progress_bar, status_label, root):
    # Running the encryption in a separate thread
    thread = threading.Thread(target=encrypt_files, args=(file_paths, key, progress_bar, status_label, root))
    thread.daemon = True  # Ensure thread ends when the main program ends
    thread.start()

def encrypt_files(file_paths, key, progress_bar, status_label, root):
    if key is None:
        return
    fernet = Fernet(key)

    # Allowed file extensions
    allowed_extensions = {".pdf", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".avi", ".mov", ".mkv"}

    unsupported_files = []  # To track unsupported files
    files_to_process = []   # Files to be encrypted

    # Check if file_paths is a list or tuple of paths, and iterate over them
    for file_path in file_paths:
        # Ensure file_path is a string and exists
        if isinstance(file_path, str):
            if os.path.isdir(file_path):  # If it's a directory, walk through it
                for root_dir, dirs, files in os.walk(file_path):
                    for file in files:
                        file_path = os.path.join(root_dir, file)
                        if '.git' not in file_path:  # Exclude .git folder files
                            if any(file.lower().endswith(ext) for ext in allowed_extensions):
                                files_to_process.append(file_path)
                            else:
                                unsupported_files.append(file_path)
            else:
                # If it's a single file, check it
                if any(file_path.lower().endswith(ext) for ext in allowed_extensions):
                    files_to_process.append(file_path)
                else:
                    unsupported_files.append(file_path)
        else:
            print(f"Skipping invalid file path: {file_path}")

    # Show a message for unsupported files if any
    if unsupported_files:
        unsupported_count = len(unsupported_files)
        messagebox.showinfo(
            "Unsupported Files Found",
            f"{unsupported_count} unsupported files were skipped during encryption.\n\n"
            f"Skipped files:\n" + "\n".join([os.path.basename(f) for f in unsupported_files[:10]]) +
            ("\n... (and more)" if unsupported_count > 10 else "")
        )

    if not files_to_process:
        messagebox.showinfo("No Supported Files", "No supported files found in the selected directory.")
        return

    progress_bar["maximum"] = len(files_to_process)

    # Encrypt each file
    for index, file_path in enumerate(files_to_process):
        try:
            with open(file_path, "rb") as f:
                # encrypted_data = fernet.encrypt(f.read())  # Encrypt file content
                file_data = f.read()
                try:
                    # Try to decrypt the file first to check if it is already encrypted
                    fernet.decrypt(file_data)  # If it decrypts successfully, it's already encrypted
                    print(f"File is already encrypted: {file_path}")
                    status_label.config(text=f"File already encrypted: {os.path.basename(file_path)}")
                    messagebox.showinfo("File Already Encrypted", f"{os.path.basename(file_path)} is already encrypted.")
                    continue  # Skip this file and continue with the next
                except InvalidToken:
                    # If decryption fails, it's not encrypted, and we can encrypt it
                    encrypted_data = fernet.encrypt(file_data)

            with open(file_path, "wb") as f:
                f.write(encrypted_data)  # Write encrypted data back to the file

            # Update progress bar and status label
            status_label.config(text=f"Encrypting: {os.path.basename(file_path)}")
            progress_bar["value"] = index + 1
            # root.update_idletask()  # Ensure the GUI updates during the process
            root.after()  # Ensure the GUI updates during the process

        except PermissionError:
            print(f"Permission denied: {file_path}. Skipping...")  # Log if permission is denied
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt {file_path}: {e}")
            continue  # Skip this file and continue with the next

    messagebox.showinfo("Success", "Encryption completed successfully!")
    status_label.config(text="Encryption completed.")


def decrypt_files_thread(file_paths, key, progress_bar, status_label, root):
    # Running the decryption in a separate thread
    thread = threading.Thread(target=decrypt_files, args=(file_paths, key, progress_bar, status_label, root))
    thread.daemon = True  # Ensure thread ends when the main program ends
    thread.start()

def decrypt_files(file_paths, key, progress_bar, status_label, root):
    if key is None:
        return
    fernet = Fernet(key)

    # Prepare list of files to process
    files_to_process = []

    # Iterate over file_paths (which can be a list or tuple of file paths)
    for file_path in file_paths:
        if isinstance(file_path, str):  # Ensure the path is a string
            if os.path.isdir(file_path):  # If it's a directory, walk through it
                for root_dir, dirs, files in os.walk(file_path):
                    for file in files:
                        file_path = os.path.join(root_dir, file)
                        files_to_process.append(file_path)
            else:
                # If it's a file, add it directly to the list
                files_to_process.append(file_path)
        else:
            print(f"Skipping invalid file path: {file_path}")

    # If there are no files to decrypt, show a message
    if not files_to_process:
        messagebox.showinfo("No Files", "No files found to decrypt.")
        return

    # Set the maximum value of the progress bar
    progress_bar["maximum"] = len(files_to_process)

    # Decrypt each file
    for index, file_path in enumerate(files_to_process):
        try:
            with open(file_path, "rb") as f:
                decrypted_data = fernet.decrypt(f.read())  # Decrypt the file content

            with open(file_path, "wb") as f:
                f.write(decrypted_data)  # Write the decrypted data back to the file

            # Update progress bar and status label
            status_label.config(text=f"Decrypting: {os.path.basename(file_path)}")
            progress_bar["value"] = index + 1
            # root.update_idletasks()  # Ensure the GUI updates during the process
            root.after()  # Ensure the GUI updates during the process

        except PermissionError:
            print(f"Permission denied: {file_path}. Skipping...")  # Log if permission is denied
        except InvalidToken:
            # If decryption fails, it's likely not encrypted
            print(f"File is already decrypted: {file_path}")
            status_label.config(text=f"File already decrypted: {os.path.basename(file_path)}")
            messagebox.showinfo("File Already Decrypted", f"{os.path.basename(file_path)} is already decrypted.")
            continue  # Skip this file and continue

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt {file_path}: {e}")
            continue  # Skip this file and continue with the next

    messagebox.showinfo("Success", "Decryption completed successfully!")
    status_label.config(text="Decryption completed.")


def select_files_encryption():
    key = load_key()  # Load encryption key

    # Open file dialog to select files (show all files)
    file_paths = filedialog.askopenfilenames(
        title="Select Files for Encryption",
        filetypes=(("All Files", "*.*"),)  # Show all file types
    )

    if file_paths:
        encrypt_files(file_paths, key,progress_bar, status_label,root)

def select_files_decryption():
    key = load_key()  # Load encryption key

    # Open file dialog to select files (show all files)
    file_paths = filedialog.askopenfilenames(
        title="Select Files for Decryption",
        filetypes=(("All Files", "*.*"),)  # Show all file types
    )

    if file_paths:
        decrypt_files(file_paths, key,progress_bar, status_label,root)


# Generate the key if it doesn't exist
generate_key()

# Ensure the script is runu with administration priveleges
run_as_admin()

# Main application window
root = tk.Tk()
root.title("Encrypt/Decrypt Files")
root.geometry("300x200")

lock_btn = tk.Button(root, text="Select files or folder for encryption", command=select_files_encryption, width=30)
lock_btn.pack(pady=10)

lock_btn = tk.Button(root, text="Select files or folder for decryption", command=select_files_decryption, width=30)
lock_btn.pack(pady=10)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress_bar.pack(pady=10)

status_label = tk.Label(root, text="", font=("Arial", 10))
status_label.pack(pady=10)

root.mainloop()
