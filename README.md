# 🌞 Sunless Password Manager Prototype 🔐
_This is a prototype of a local password manager with open-source code in Python._  
**Not for real secrets. For fun, learning, and experiments only!** 😎⚡

---

## ⚠️ Important

**Sunless Password Manager is a prototype!**  
It is **not intended for storing real confidential data in a production environment**.  
Use at your own risk! 👀  
The code is provided for educational, testing, and further development purposes only. 🧪🛠️

---

**⚠️ Support the project 🛡️** 
ETH: 0xF7c9B5Da072bE02F0dd8bc51Ae67ba05925D27EF
![QR]https://github.com/sunless6/SunlessPasswordManager-Proto/blob/main/qr.png


---

## ✨ Features

- 🗃️ **Local-only storage** — passwords are kept in an encrypted file, no internet needed!
- 🛡️ **Double encryption layer:** outer & master passwords
- 🔒 Uses **AES-256-GCM** (authenticated encryption), **RSA-2048-OAEP**, and **PBKDF2**
- 📱 **2FA support** (Google Authenticator / TOTP)
- 🧬 Strong password generator with one click
- 🎨 Simple & friendly UI (Tkinter)
- 🚀 Fast search and easy management of records
- 📝 Support for notes and links per entry
- 🧑‍💻 **Open source** — hack, learn, and improve!

---

## 🚀 Getting Started

1. **Install dependencies**:
    ```bash
    pip install pyotp cryptography pillow qrcode
    ```

2. **Run the app**:
    ```bash
    python main.py
    ```

---

## 🛡️ Security

- All your data is protected by **double encryption**! 🔐🔐
- Uses modern cryptographic algorithms 🧊
- **BUT:**  
  - Key sizes and some design decisions were made for prototyping and may not be secure enough for real secrets ⚠️
  - No protection if your computer is compromised 🖥️💣
  - **Use only for testing and experiments!** 🎲

---

## 📝 TODO

- 🕵️‍♂️ Audit and improve cryptography
- 💎 Better UI/UX
- 💾 Backup, import/export features
- 🏳️‍🌈 More flexible security policies
- 🧩 Plugins? Themes? Who knows!

---

## 📃 License

MIT License 📜

---

**Sunless Password Manager Prototype**  
By [sunless6](https://github.com/sunless6) 🚀🌙

