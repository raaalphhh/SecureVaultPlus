# 🔐 SecureVault+

**SecureVault+** is a lightweight, terminal-based password vault written in **C** that uses **AES-128 encryption (CBC mode)** via **OpenSSL** to store and manage credentials securely. It supports setting a master password, secure login, encrypted credential storage, import/export, and a recovery system using security questions or OTP fallback.

> 🚧 **This project is currently under construction.** Features may change or improve over time. Contributions, suggestions, or testing are welcome!

---

## 📌 Why SecureVault+?

In an era where security breaches are common, SecureVault+ offers a minimal, open-source solution for managing sensitive credentials directly on your local machine—no internet required, no third-party cloud risks.

---

## 🛠 Features

- ✅ Set & reset a master password
- 🔐 AES-128-CBC encryption using OpenSSL
- 👤 Login authentication via password hashing
- 🔄 Recovery system via:
  - Security Question (encrypted)
  - OTP fallback simulation (for future email OTP)
- 🗂 Import/Export encrypted vault file (`vault.dat`)
- 🤫 Password input masking (cross-platform)
- 🔢 Salted key derivation using PBKDF2 (OpenSSL)
- 📜 Clean and readable codebase for students or C learners
- 🧱 Uses custom binary structure for each credential
- 📦 Packaged data includes site, username, encrypted password, IV

---

## 🧪 Under Development

Planned and upcoming features:

- ✉️ Real email-based OTP via SMTP integration
- 🧹 Ability to **delete or edit** credentials
- 🖥️ GUI version (possibly in C++/Qt or Electron)
- 🔒 Timed auto-logout
- 🧾 Audit log for credential access history
- 🌐 Cross-platform build support and install script
- 📁 Encrypted vault backup with versioning


---

## 🧪 Requirements

- ✅ GCC compiler (or compatible C compiler)
- ✅ [OpenSSL](https://www.openssl.org/) installed
- 🔀 Optional: Git, Make, or CMake for better build flow

---

## 🚀 How to Compile and Run

### 🔧 Compile on Windows/Linux/macOS:

```bash
gcc main.c aes.c auth.c vault.c recovery.c utils.c -o vault -lssl -lcrypto
./vault
