# PrivacyOS
PrivacyOS Enterprise Suite — An elite, zero-trust cybersecurity and encrypted intelligence platform featuring 3D cybernetic terminal workflows, AES-256-GCM encryption, steganography, post-login MFA OTP verification, zero-knowledge password vaults, and automated AST code security scanners.


# 🛡️ PrivacyOS Enterprise Suite

PrivacyOS is a full-stack, zero-trust cybersecurity platform engineered to function as a military-grade intelligence command center. It combines advanced cryptography, image steganography, real-time encrypted communications, zero-knowledge storage, and automated static code analysis into a unified cyberpunk dashboard.

## 🚀 Core Features & Architecture

1. **Authentication & Multi-Factor Authentication (MFA):**
   - Secure registration and mandatory post-login verification using 6-digit OTPs dispatched via Postman SMTP.
   - Built with enterprise security headers and JWT-based session controls.

2. **Terminal A & B (Encryption, Steganography & Forensics):**
   - **Direct Transfer:** Standard AES-256-GCM file encryption.
   - **Ghost Mode (Level 3):** Mandatory steganography (hiding secret payloads inside image pixels), forensic watermarking for mole identification, automated 60-minute time-bombs, and 3-strike hacker tripwires that permanently shred payloads upon brute-force detection.
   - **Duress Protocol:** Entering `MAYDAY` as an extraction key triggers a silent audit log alarm while returning a harmless corporate decoy file.

3. **Secure Signal-Style Comms:**
   - Real-time bidirectional messaging tunnels powered by WebSockets (`/ws/chat`).
   - Agent contact roster search and directory integration.

4. **Zero-Knowledge (ZK) Password Vault:**
   - Client-side encryption using the Web Crypto API (AES-GCM & PBKDF2) *before* data ever leaves the browser. The server has zero knowledge of user master passphrases or plaintext keys.

5. **Code Security & Secret Scanner:**
   - Static analysis engine scanning Abstract Syntax Trees and regular expressions for hardcoded API keys (e.g., AWS, Google tokens), weak hashing algorithms, and injection flaws, returning an instant security audit grade (A–F).

6. **Cinematic 3D Cybernetic Interface:**
   - Built with **Three.js** rendering an interactive, rotating wireframe globe and particle telemetry field, paired with a sleek Bootstrap 5 dark-mode command center.

## 🛠️ Tech Stack
* **Backend:** Python FastAPI, SQLAlchemy ORM, SQLite/PostgreSQL, WebSockets, Cryptography, Pydantic.
* **Frontend:** Bootstrap 5, Vanilla JavaScript, Three.js (3D graphics), QRCode.js.
* **Security Standards:** AES-256-GCM, PBKDF2, Out-of-Band (OOB) Channel Separation for encryption keys.

---
*Developed for elite zero-trust operational security.*
