# QuantaCrypt – Dual-Layer Quantum-Safe File Protection (Project Idea)

**QuantaCrypt** is a hybrid cryptographic model that secures files using **two independent key layers**:

### 🔐 1. Quantum-Inspired Key Layer (Simulated QKD)
A BB84-style quantum key distribution simulation generates a random, high-entropy secret key.  
This provides a “quantum-level” randomness source.

### 🔒 2. Post-Quantum Key Layer (Simulated Kyber-like KEM)
A Kyber-inspired, lattice-style KEM simulation produces a second independent shared secret.

### ⚡ Hybrid Key Fusion
Both keys are fused using SHA3-512:

HybridKey = SHA3-512(QKD_key || PQC_key)

This hybrid key powers all encryption operations.

### 🧊 AES-256-GCM File Encryption
Files of any type are encrypted using AES-256-GCM with:
- Integrity  
- Authentication  
- Non-malleability  

### ✒️ PQC-Style Digital Signatures
A Dilithium-like signature simulation signs the encrypted file so the receiver can verify authenticity.

### 📜 Tamper-Evident Audit Log
Every encryption, decryption, signature verification, or key event is logged in:
- A hash-chained ledger  
- Digitally signed for tamper evidence  

### 🔄 End-to-End Workflow
1. QKD key generation  
2. PQC KEM shared secret  
3. Hybrid key derivation  
4. File encryption  
5. PQC signature  
6. Audit logging  
7. Receiver verification  
8. File decryption  

### 🎯 Purpose of the Project
To demonstrate a **quantum-resilient file protection architecture** using:
- Hybrid key exchange  
- Authenticated encryption  
- Post-quantum signatures  
- Forensic-grade audit logs  

This showcases how future-proof cryptographic systems can be built today.
