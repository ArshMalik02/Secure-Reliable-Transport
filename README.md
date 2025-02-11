# Secure Reliable Transport Protocol (SRTP)

## Overview
SRTP is a custom-built transport layer protocol over UDP, designed to ensure **reliable data transfer** and **secure communication**. This project was developed as part of CS 118: Computer Network Fundamentals, and consists of two phases:

1. **Reliable Transport Layer:** Implements a TCP-like protocol over UDP with features like sequencing, acknowledgments, retransmissions, and flow control.
2. **Security Layer:** Adds encryption, authentication, and integrity checks to protect data transmission from tampering and eavesdropping.

## Features
### 🚀 **Reliable Transport (Project 1)**
- Implements a **three-way handshake** for connection establishment.
- Uses **sequencing and acknowledgments** to ensure in-order delivery.
- Implements **selective retransmissions** and **window-based flow control** for efficiency.
- Handles **packet loss and reordering** using a timeout-based retransmission strategy.

### 🔒 **Security Layer (Project 2)**
- Implements **TLS-like encryption** using **AES-256-CBC** for confidentiality.
- Uses **Diffie-Hellman key exchange** for secure session key generation.
- Ensures message integrity with **HMAC-SHA256 authentication**.
- Implements **digital signatures (ECDSA)** for client-server authentication.
