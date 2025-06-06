import os
import json
import base64
import threading
import secrets
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
from cryptography.exceptions import InvalidTag
import pyotp
import qrcode
from PIL import Image, ImageTk

from cryptography_tools import (
    PBKDF2_SALT_SIZE, AES_KEY_SIZE, generate_salt, derive_key,
    aes_encrypt, aes_decrypt, generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    serialize_private_key, serialize_public_key, deserialize_private_key, deserialize_public_key,
    secure_zero,
    ext_generate_rsa_keypair, ext_generate_aes_key, ext_aes_encrypt, ext_aes_decrypt,
    rsa_encrypt as ext_rsa_encrypt, rsa_decrypt as ext_rsa_decrypt,
    serialize_private_key as ext_serialize_private_key, serialize_public_key as ext_serialize_public_key,
    deserialize_private_key as ext_deserialize_private_key, deserialize_public_key as ext_deserialize_public_key,
    generate_totp_secret
)

SESSION_TIMEOUT = 300

class Storage:
    def __init__(self, path):
        self.path = path
        self.data = None

    def exists(self):
        return os.path.exists(self.path)

    def load(self):
        with open(self.path, "rb") as f:
            self.data = f.read()

    def save(self, raw_data: bytes):
        with open(self.path, "wb") as f:
            f.write(raw_data)
        try:
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        except Exception:
            pass

class ExternalEncryptionLayer:
    """
    Внешний слой шифрования всего файла. Все поля - base64!
    """
    def __init__(self, meta=None):
        self.salt = None
        self.enc_priv = None
        self.enc_aes = None
        self.pub = None
        self.enc = None
        self.iv = None
        self.tag = None
        if meta:
            self.__dict__.update(meta)

    @staticmethod
    def wrap(data: bytes, outer_password: str):
        ext_priv, ext_pub = ext_generate_rsa_keypair()
        ext_aes = ext_generate_aes_key()
        ext_salt = generate_salt(16)
        outer_key = derive_key(outer_password, ext_salt, length=16)
        enc_priv = aes_encrypt(ext_serialize_private_key(ext_priv), outer_key)
        enc_aes = ext_rsa_encrypt(ext_pub, ext_aes)
        enc = ext_aes_encrypt(data, ext_aes)
        meta = {
            "salt": base64.b64encode(ext_salt).decode(),
            "enc_priv": enc_priv,
            "enc_aes": enc_aes,
            "pub": base64.b64encode(ext_serialize_public_key(ext_pub)).decode(),
            "enc": {"iv": enc["iv"], "data": enc["data"], "tag": enc["tag"]},
        }
        # Очистка памяти
        secure_zero(ext_aes)
        return ExternalEncryptionLayer(meta)

    @staticmethod
    def unwrap(raw: bytes, outer_password: str):
        meta = json.loads(raw.decode())
        salt = base64.b64decode(meta["salt"])
        outer_key = derive_key(outer_password, salt, length=16)
        priv_bytes = aes_decrypt(meta["enc_priv"], outer_key)
        ext_priv = ext_deserialize_private_key(priv_bytes)
        ext_aes = ext_rsa_decrypt(ext_priv, meta["enc_aes"])
        enc_data = meta["enc"]
        decrypted = ext_aes_decrypt(enc_data, ext_aes)
        # Очистка
        secure_zero(ext_aes)
        return decrypted, ExternalEncryptionLayer(meta)

    def to_bytes(self):
        return json.dumps({
            "salt": self.salt,
            "enc_priv": self.enc_priv,
            "enc_aes": self.enc_aes,
            "pub": self.pub,
            "enc": self.enc,
        }).encode()

class SunlessPasswordEntry(tk.Frame):
    def __init__(self, master, site, username, password, notes, url, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.site = site
        self.username = username
        self.password = password
        self.notes = notes
        self.url = url
        self.show_password = False
        self.expanded = False

        self.bg_default = "#fff"
        self.bg_hover = "#f1f3f4"
        self.configure(bg=self.bg_default)
        self.bind("<Enter>", lambda e: self.configure(bg=self.bg_hover))
        self.bind("<Leave>", lambda e: self.configure(bg=self.bg_default))

        self.header = tk.Frame(self, bg=self.bg_default)
        self.header.pack(fill='x', padx=0, pady=0)
        self.site_icon = tk.Label(self.header, text="🌐", font=('Arial', 16), bg=self.bg_default)
        self.site_icon.pack(side='left', padx=(4,4), pady=8)
        self.site_label = tk.Label(self.header, text=site, font=('Arial', 13, 'bold'), bg=self.bg_default)
        self.site_label.pack(side='left', padx=(0,4))
        self.username_label = tk.Label(self.header, text=username, font=('Arial', 11), fg="#757575", bg=self.bg_default)
        self.username_label.pack(side='left', padx=(0,4))
        self.expand_button = tk.Button(self.header, text='▶', font=('Arial', 10), bd=0, bg=self.bg_default, activebackground=self.bg_hover, command=self.toggle_expand)
        self.expand_button.pack(side='right', padx=8)
        self.expand_button.bind("<Enter>", lambda e: self.expand_button.config(bg="#e0e0e0"))
        self.expand_button.bind("<Leave>", lambda e: self.expand_button.config(bg=self.bg_default))
        self.separator = tk.Frame(self, height=1, bg="#e0e0e0")
        self.separator.pack(fill='x', side='bottom', pady=(0,0))
        self.details_frame = tk.Frame(self, bg="#f8fafd")
        self.details_frame.pack(fill='x', padx=36, pady=(0,8))
        self.details_frame.pack_forget()
        tk.Label(self.details_frame, text="Имя пользователя", font=('Arial', 10), bg="#f8fafd", fg="#757575").grid(row=0, column=0, sticky='w')
        tk.Label(self.details_frame, text=username, font=('Arial', 10), bg="#f8fafd").grid(row=0, column=1, sticky='w', padx=(10,0))
        tk.Label(self.details_frame, text="Пароль", font=('Arial', 10), bg="#f8fafd", fg="#757575").grid(row=1, column=0, sticky='w', pady=4)
        self.password_var = tk.StringVar(value='•' * len(password))
        self.password_label = tk.Label(self.details_frame, textvariable=self.password_var, font=('Arial', 12), bg="#f8fafd")
        self.password_label.grid(row=1, column=1, sticky='w', padx=(10,0), pady=4)
        self.eye_icon = tk.Button(self.details_frame, text='👁️', bd=0, font=('Arial', 11), bg="#f8fafd", command=self.toggle_password, cursor="hand2")
        self.eye_icon.grid(row=1, column=2, padx=(6,3))
        self.copy_icon = tk.Button(self.details_frame, text='📋', bd=0, font=('Arial', 11), bg="#f8fafd", command=self.copy_password, cursor="hand2")
        self.copy_icon.grid(row=1, column=3, padx=3)
        tk.Label(self.details_frame, text="URL", font=('Arial', 10), bg="#f8fafd", fg="#757575").grid(row=2, column=0, sticky='w')
        tk.Label(self.details_frame, text=self.url, font=('Arial', 10), bg="#f8fafd", fg="#388e3c").grid(row=2, column=1, sticky='w', padx=(10,0))
        tk.Label(self.details_frame, text="Заметки", font=('Arial', 10), bg="#f8fafd", fg="#757575").grid(row=3, column=0, sticky='w')
        tk.Label(self.details_frame, text=self.notes, font=('Arial', 10), bg="#f8fafd", fg="#1976d2", wraplength=250, justify="left").grid(row=3, column=1, sticky='w', padx=(10,0))

    def toggle_expand(self):
        if self.expanded:
            self.details_frame.pack_forget()
            self.expand_button.config(text='▶')
        else:
            self.details_frame.pack(fill='x', padx=36, pady=(0,8))
            self.expand_button.config(text='▼')
        self.expanded = not self.expanded

    def toggle_password(self):
        self.show_password = not self.show_password
        if self.show_password:
            self.password_var.set(self.password)
            self.eye_icon.config(text='🚫')
        else:
            self.password_var.set('•' * len(self.password))
            self.eye_icon.config(text='👁️')

    def copy_password(self):
        self.clipboard_clear()
        self.clipboard_append(self.password)
        messagebox.showinfo("Скопировано", "Пароль скопирован в буфер обмена!")
        self.after(1500, self.secure_clipboard)

    def secure_clipboard(self):
        self.clipboard_clear()

    def clipboard_clear(self):
        self.winfo_toplevel().clipboard_clear()

    def clipboard_append(self, text):
        self.winfo_toplevel().clipboard_append(text)

class SunlessPasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sunless Password Manager")
        self.geometry('560x690')
        self.config(bg="#f8fafd")
        self.resizable(False, False)
        self.storage_file = None
        self.storage = None
        self.outer_password = None
        self.outer_meta = None
        self.inner_json = None
        self.master_key = None
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.session_active = False
        self.session_timer = None
        self.totp_secret = None
        self._build_login_screen()

    def _build_login_screen(self):
        for w in self.winfo_children():
            w.destroy()
        login_frame = tk.Frame(self, bg="#f8fafd")
        login_frame.place(relx=0.5, rely=0.5, anchor='c')
        tk.Label(login_frame, text="🔒", font=('Arial', 40), bg="#f8fafd").pack(pady=(0,20))
        tk.Label(login_frame, text="Sunless Password Manager", font=('Arial', 16, "bold"), bg="#f8fafd").pack(pady=(0,16))
        tk.Button(login_frame, text="Открыть хранилище", font=("Arial", 12), width=30, command=self.open_existing_storage).pack(pady=6)
        tk.Button(login_frame, text="Создать новое хранилище", font=("Arial", 12), width=30, command=self.create_new_storage).pack(pady=6)
        tk.Button(login_frame, text="Выход", font=("Arial", 12), width=30, command=self.quit).pack(pady=(28,4))

    def open_existing_storage(self):
        file = filedialog.askopenfilename(title="Выберите файл хранилища", filetypes=(("Valera files", "*.valera"),("JSON files", "*.json")))
        if not file:
            return
        self.storage_file = file
        self.storage = Storage(self.storage_file)
        self.storage.load()
        outer_password = simpledialog.askstring("Внешний пароль", "Введите внешний пароль:", show="*")
        if not outer_password:
            return
        try:
            decrypted, outer_meta = ExternalEncryptionLayer.unwrap(self.storage.data, outer_password)
        except InvalidTag:
            messagebox.showerror("Ошибка", "Неверный внешний пароль.")
            return
        except Exception:
            messagebox.showerror("Ошибка", "Ошибка внешнего слоя, возможно повреждение файла!")
            return
        self.outer_password = outer_password
        self.outer_meta = outer_meta
        self.inner_json = json.loads(decrypted.decode('utf-8'))
        if "totp_secret" in self.inner_json and self.inner_json["totp_secret"]:
            self._prompt_2fa(self.inner_json["totp_secret"])
        else:
            self._show_password_prompt("Введите мастер-пароль хранилища")

    def create_new_storage(self):
        file = filedialog.asksaveasfilename(title="Создать новый файл хранилища", defaultextension=".valera", filetypes=(("Valera files", "*.valera"),("JSON files", "*.json")))
        if not file:
            return
        outer_password = simpledialog.askstring("Внешний пароль", "Придумайте внешний пароль:", show="*")
        if not outer_password:
            return
        password = self._ask_two_passwords("Создать мастер-пароль")
        if not password:
            return
        salt = generate_salt()
        key = derive_key(password, salt)
        priv_key, pub_key = generate_rsa_keypair()
        priv_bytes = serialize_private_key(priv_key)
        enc_priv = aes_encrypt(priv_bytes, key)
        pub_bytes = serialize_public_key(pub_key)
        inner_json = {
            "salt": base64.b64encode(salt).decode(),
            "rsa_private": enc_priv,
            "rsa_public": base64.b64encode(pub_bytes).decode(),
            "vault": [],
            "totp_secret": "",
        }
        raw_inner = json.dumps(inner_json).encode()
        ext_layer = ExternalEncryptionLayer.wrap(raw_inner, outer_password)
        storage = Storage(file)
        storage.save(ext_layer.to_bytes())
        messagebox.showinfo("Готово", "Хранилище успешно создано!")
        self._build_login_screen()

    def _ask_two_passwords(self, title):
        pw1 = simpledialog.askstring(title, "Введите мастер-пароль:", show="*")
        if not pw1:
            return None
        pw2 = simpledialog.askstring(title, "Повторите мастер-пароль:", show="*")
        if pw1 != pw2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return None
        return pw1

    def _show_password_prompt(self, prompt):
        pw = simpledialog.askstring("Мастер-пароль", prompt, show="*")
        if not pw:
            return
        salt = base64.b64decode(self.inner_json["salt"])
        enc_priv = self.inner_json["rsa_private"]
        try:
            key = derive_key(pw, salt)
            priv_bytes = aes_decrypt(enc_priv, key)
            priv_key = deserialize_private_key(priv_bytes)
            pub_bytes = base64.b64decode(self.inner_json["rsa_public"])
            pub_key = deserialize_public_key(pub_bytes)
            self.master_key = bytearray(key)
            self.rsa_private_key = priv_key
            self.rsa_public_key = pub_key
            self.session_active = True
            self._build_main_screen()
            self._start_session_timer()
            secure_zero(self.master_key)
        except InvalidTag:
            messagebox.showerror("Ошибка", "Неверный мастер-пароль.")
        except Exception as e:
            print(f"Ошибка при расшифровке ключа или хранилище повреждено: {type(e).__name__}: {str(e)}")
            messagebox.showerror("Ошибка", "Ошибка при расшифровке ключа или хранилище повреждено.")
            self._build_login_screen()

    def _prompt_2fa(self, secret):
        code = simpledialog.askstring("2FA", "Введите 6-значный код из Google Authenticator:")
        if not code:
            return
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            self._show_password_prompt("Введите мастер-пароль хранилища")
        else:
            messagebox.showerror("Ошибка", "Неверный код 2FA")
            self._prompt_2fa(secret)

    def _build_main_screen(self):
        for w in self.winfo_children():
            w.destroy()
        self.topbar = tk.Frame(self, bg="#fff", height=54, highlightbackground="#e0e0e0", highlightthickness=1)
        self.topbar.pack(side='top', fill='x')
        self.logo = tk.Label(self.topbar, text="🔒", font=('Arial', 18), bg="#fff")
        self.logo.pack(side='left', padx=12, pady=8)
        self.title_label = tk.Label(self.topbar, text="Менеджер паролей", font=('Arial', 15, "bold"), bg="#fff")
        self.title_label.pack(side='left', padx=(2,0), pady=8)
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(self.topbar, textvariable=self.search_var, font=('Arial', 11), relief='flat', bg="#f1f3f4", width=22)
        self.search_entry.pack(side='left', padx=26)
        self.search_entry.insert(0, "Поиск")
        self.search_var.trace("w", lambda *args: self._update_password_list())
        self.account_btn = tk.Button(self.topbar, text="🧑", bd=0, font=('Arial', 15), bg="#fff", command=self._show_account_menu, cursor="hand2")
        self.account_btn.pack(side='right', padx=16)
        self.list_label = tk.Label(self, text="Сайты", font=("Arial", 12, "bold"), bg="#f8fafd", anchor="w")
        self.list_label.pack(fill='x', padx=24, pady=(18,0))
        self.list_frame = tk.Frame(self, bg="#f8fafd")
        self.list_frame.pack(fill='both', expand=True, padx=10, pady=(4,0))
        self.add_btn = tk.Button(self, text="Добавить запись", font=("Arial", 12), bg="#1976d2", fg="#fff", command=self.add_record, relief="flat", cursor="hand2")
        self.add_btn.pack(side='bottom', pady=10, ipady=3)
        self._update_password_list()

    def _update_password_list(self):
        for w in self.list_frame.winfo_children():
            w.destroy()
        vault = self.inner_json["vault"]
        q = self.search_var.get().lower()
        for idx, entry in enumerate(vault):
            try:
                aes_key = rsa_decrypt(self.rsa_private_key, entry["enc_key"])
                plaintext = aes_decrypt(entry["enc"], aes_key)
                dec = json.loads(plaintext.decode('utf-8'))
                if (q == "поиск" or
                    q in dec["name"].lower() or
                    q in dec["login"].lower() or
                    q in dec.get("url", "").lower()):
                    pe = SunlessPasswordEntry(self.list_frame, dec["name"], dec["login"], dec["password"], dec.get("notes", ""), dec.get("url", ""))
                    pe.pack(fill='x', pady=2)
                    pe.bind('<Button-3>', lambda e, idx=idx: self._show_entry_menu(e, idx))
                secure_zero(aes_key)
                if isinstance(plaintext, bytearray):
                    secure_zero(plaintext)
            except InvalidTag:
                error_label = tk.Label(self.list_frame, text=f"Запись {idx+1}: Ошибка данных (повреждена?)", fg="red", bg="#f8fafd")
                error_label.pack(fill='x', pady=1)
            except Exception as e:
                error_label = tk.Label(self.list_frame, text=f"Запись {idx+1}: Не удалось прочитать ({type(e).__name__})", fg="red", bg="#f8fafd")
                error_label.pack(fill='x', pady=1)

    def add_record(self):
        dialog = RecordDialog(self, "Добавить запись")
        self.wait_window(dialog)
        if dialog.result:
            name, url, login, password, notes = dialog.result
            aes_key = secrets.token_bytes(AES_KEY_SIZE)
            record_data = json.dumps({
                "name": name, "url": url, "login": login, "password": password, "notes": notes
            }).encode()
            enc = aes_encrypt(record_data, aes_key)
            enc_key = rsa_encrypt(self.rsa_public_key, aes_key)
            entry = {"enc": enc, "enc_key": enc_key}
            self.inner_json["vault"].append(entry)
            self._save_storage()
            self._update_password_list()
            secure_zero(aes_key)
            if isinstance(record_data, bytearray):
                secure_zero(record_data)

    def _save_storage(self):
        raw_inner = json.dumps(self.inner_json).encode()
        ext_layer = ExternalEncryptionLayer.wrap(raw_inner, self.outer_password)
        self.storage.save(ext_layer.to_bytes())

    def _show_entry_menu(self, event, idx):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Редактировать", command=lambda: self.edit_record(idx))
        menu.add_command(label="Удалить", command=lambda: self.delete_record(idx))
        menu.tk_popup(event.x_root, event.y_root)

    def edit_record(self, idx):
        entry = self.inner_json["vault"][idx]
        aes_key = rsa_decrypt(self.rsa_private_key, entry["enc_key"])
        plaintext = aes_decrypt(entry["enc"], aes_key)
        dec = json.loads(plaintext.decode('utf-8'))
        dialog = RecordDialog(self, "Редактировать запись", dec)
        self.wait_window(dialog)
        if dialog.result:
            name, url, login, password, notes = dialog.result
            aes_key2 = secrets.token_bytes(AES_KEY_SIZE)
            record_data = json.dumps({
                "name": name, "url": url, "login": login, "password": password, "notes": notes
            }).encode()
            enc = aes_encrypt(record_data, aes_key2)
            enc_key = rsa_encrypt(self.rsa_public_key, aes_key2)
            self.inner_json["vault"][idx] = {"enc": enc, "enc_key": enc_key}
            self._save_storage()
            self._update_password_list()
            secure_zero(aes_key2)
            if isinstance(record_data, bytearray):
                secure_zero(record_data)
        secure_zero(aes_key)
        if isinstance(plaintext, bytearray):
            secure_zero(plaintext)

    def delete_record(self, idx):
        if messagebox.askyesno("Удаление", "Удалить эту запись?"):
            del self.inner_json["vault"][idx]
            self._save_storage()
            self._update_password_list()

    def _show_account_menu(self):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Сменить мастер-пароль", command=self.change_master_password)
        menu.add_command(label="Сменить внешний пароль", command=self.change_outer_password)
        menu.add_separator()
        menu.add_command(label="2FA: Привязать Google Authenticator", command=self.attach_2fa)
        menu.add_command(label="2FA: Отключить 2FA", command=self.detach_2fa)
        menu.add_separator()
        menu.add_command(label="Заблокировать/выйти", command=self.logout)
        menu.tk_popup(self.account_btn.winfo_rootx(), self.account_btn.winfo_rooty() + 35)

    def change_master_password(self):
        old_pw = simpledialog.askstring("Смена пароля", "Введите текущий мастер-пароль:", show="*")
        if not old_pw:
            return
        salt = base64.b64decode(self.inner_json["salt"])
        try:
            old_key = derive_key(old_pw, salt)
            priv_bytes = aes_decrypt(self.inner_json["rsa_private"], old_key)
        except InvalidTag:
            messagebox.showerror("Ошибка", "Текущий мастер-пароль неверен.")
            return
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка при проверке пароля: {e}")
            return
        new_pw = self._ask_two_passwords("Новый мастер-пароль")
        if not new_pw:
            return
        new_salt = generate_salt()
        new_key = derive_key(new_pw, new_salt)
        enc_priv = aes_encrypt(priv_bytes, new_key)
        self.inner_json["salt"] = base64.b64encode(new_salt).decode()
        self.inner_json["rsa_private"] = enc_priv
        self._save_storage()
        messagebox.showinfo("Готово", "Мастер-пароль изменён.")
        secure_zero(old_key)
        secure_zero(new_key)
        secure_zero(priv_bytes)

    def change_outer_password(self):
        old_pw = simpledialog.askstring("Внешний пароль", "Введите текущий внешний пароль:", show="*")
        if not old_pw or old_pw != self.outer_password:
            messagebox.showerror("Ошибка", "Внешний пароль неверен.")
            return
        new_pw = simpledialog.askstring("Внешний пароль", "Введите новый внешний пароль:", show="*")
        if not new_pw:
            return
        raw_inner = json.dumps(self.inner_json).encode()
        ext_layer = ExternalEncryptionLayer.wrap(raw_inner, new_pw)
        self.storage.save(ext_layer.to_bytes())
        self.outer_password = new_pw
        messagebox.showinfo("Готово", "Внешний пароль изменён.")

    def attach_2fa(self):
        if self.inner_json.get("totp_secret"):
            messagebox.showinfo("2FA", "2FA уже привязан.")
            return
        secret = generate_totp_secret()
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name="SunlessPasswordManager", issuer_name="Sunless")
        qr = qrcode.make(totp_uri)
        qr = qr.resize((200, 200))
        top = tk.Toplevel(self)
        top.title("QR для Google Authenticator")
        qr_img = ImageTk.PhotoImage(qr)
        lbl = tk.Label(top, image=qr_img)
        lbl.image = qr_img
        lbl.pack()
        tk.Label(top, text=f"Секрет: {secret}", font=("Arial", 10)).pack()
        code = simpledialog.askstring("2FA", "Введите 6-значный код из Google Authenticator для подтверждения:")
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            self.inner_json["totp_secret"] = secret
            self._save_storage()
            messagebox.showinfo("2FA", "2FA успешно привязан.")
            top.destroy()
        else:
            messagebox.showerror("2FA", "Код неверен, попробуйте ещё раз.")
            top.destroy()

    def detach_2fa(self):
        if not self.inner_json.get("totp_secret"):
            messagebox.showinfo("2FA", "2FA не привязан.")
            return
        code = simpledialog.askstring("2FA", "Введите 6-значный код Google Authenticator для отключения:")
        if pyotp.TOTP(self.inner_json["totp_secret"]).verify(code, valid_window=1):
            self.inner_json["totp_secret"] = ""
            self._save_storage()
            messagebox.showinfo("2FA", "2FA отключён.")
        else:
            messagebox.showerror("2FA", "Код неверен.")

    def logout(self):
        self.session_active = False
        self.master_key = None
        self.rsa_private_key = None
        self.rsa_public_key = None
        if self.session_timer:
            self.session_timer.cancel()
        self._build_login_screen()

    def _start_session_timer(self):
        if self.session_timer:
            self.session_timer.cancel()
        self.session_timer = threading.Timer(SESSION_TIMEOUT, self._auto_lock)
        self.session_timer.daemon = True
        self.session_timer.start()

    def _auto_lock(self):
        messagebox.showinfo("Блокировка", "Сессия заблокирована по таймауту.")
        self.logout()

class RecordDialog(tk.Toplevel):
    def __init__(self, parent, title, data=None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result = None
        tk.Label(self, text="Название сервиса:").grid(row=0, column=0, sticky='w', padx=10, pady=(12,0))
        self.name_var = tk.StringVar(value=(data["name"] if data else ""))
        tk.Entry(self, textvariable=self.name_var, width=32).grid(row=0, column=1, columnspan=2, padx=10, pady=(12,0))
        tk.Label(self, text="URL:").grid(row=1, column=0, sticky='w', padx=10)
        self.url_var = tk.StringVar(value=(data["url"] if data else ""))
        tk.Entry(self, textvariable=self.url_var, width=32).grid(row=1, column=1, columnspan=2, padx=10)
        tk.Label(self, text="Логин:").grid(row=2, column=0, sticky='w', padx=10)
        self.login_var = tk.StringVar(value=(data["login"] if data else ""))
        tk.Entry(self, textvariable=self.login_var, width=32).grid(row=2, column=1, columnspan=2, padx=10)
        tk.Label(self, text="Пароль:").grid(row=3, column=0, sticky='w', padx=10)
        self.password_var = tk.StringVar(value=(data["password"] if data else ""))
        self.show_password = False
        self.pw_entry = tk.Entry(self, textvariable=self.password_var, width=24, show="*")
        self.pw_entry.grid(row=3, column=1, padx=(10,0), sticky='w')
        self.eye_btn = tk.Button(self, text="👁️", width=3, command=self.toggle_password, relief='flat', bg="white")
        self.eye_btn.grid(row=3, column=2, padx=(2,0), sticky='w')
        self.copy_btn = tk.Button(self, text="📋", width=3, command=self.copy_password, relief='flat', bg="white")
        self.copy_btn.grid(row=3, column=3, padx=(2,10), sticky='w')
        gen_btn = tk.Button(self, text="Генерировать", command=self._gen_password)
        gen_btn.grid(row=3, column=4, padx=(2,10), sticky='w')
        tk.Label(self, text="Заметки:").grid(row=4, column=0, sticky='nw', padx=10, pady=(0,6))
        self.notes_var = tk.Text(self, width=32, height=3)
        self.notes_var.grid(row=4, column=1, columnspan=4, padx=10, pady=(0,6))
        if data:
            self.notes_var.insert('1.0', data.get("notes", ""))
        btn_frame = tk.Frame(self)
        btn_frame.grid(row=5, column=0, columnspan=5, pady=10)
        self.save_btn = tk.Button(btn_frame, text="Сохранить", command=self._save)
        self.save_btn.pack(side='left', padx=10)
        tk.Button(btn_frame, text="Отмена", command=self.destroy).pack(side='left', padx=10)
        self.grab_set()
        self.name_var.trace("w", lambda *a: self._check_enable())
        self._check_enable()

    def _check_enable(self):
        self.save_btn.config(state="normal" if self.name_var.get().strip() else "disabled")

    def toggle_password(self):
        self.show_password = not self.show_password
        if self.show_password:
            self.pw_entry.config(show="")
            self.eye_btn.config(text="🚫")
        else:
            self.pw_entry.config(show="*")
            self.eye_btn.config(text="👁️")

    def copy_password(self):
        password = self.password_var.get()
        self.clipboard_clear()
        self.clipboard_append(password)
        self.copy_btn.config(text="✅")
        self.after(1000, lambda: self.copy_btn.config(text="📋"))
        self.after(1500, self.clipboard_clear)

    def clipboard_clear(self):
        self.winfo_toplevel().clipboard_clear()

    def clipboard_append(self, text):
        self.winfo_toplevel().clipboard_append(text)

    def _gen_password(self):
        length = simpledialog.askinteger("Длина пароля", "Введите длину пароля (min 8, max 64):", initialvalue=16, minvalue=8, maxvalue=64)
        if not length:
            return
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?"
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        self.password_var.set(pw)
        self.show_password = True
        self.pw_entry.config(show="")
        self.eye_btn.config(text="🚫")

    def _save(self):
        notes = self.notes_var.get("1.0", "end-1c")
        self.result = (
            self.name_var.get(),
            self.url_var.get(),
            self.login_var.get(),
            self.password_var.get(),
            notes
        )
        self.destroy()

if __name__ == "__main__":
    SunlessPasswordManagerApp().mainloop()