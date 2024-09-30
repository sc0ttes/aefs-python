# aefs-python

Asymmetric Encryption File System in Python

## Introduction

**AEFS** is a Python-based FUSE filesystem that provides transparent encryption and decryption of files using hybrid (asymmetric and symmetric) cryptography. It allows users to securely encrypt files with a public key and decrypt them with the corresponding private key. The filesystem operates in two distinct modes:

- **Encryption Mode (Write-Only)**: Encrypt files using a public key.
- **Decryption Mode (Read-Only)**: Decrypt files using a private key.

This approach ensures that sensitive data remains confidential and can only be accessed by authorized parties holding the private key.

## ** Important Note **

This project has not been cryptographically audited and should not be used in production systems. Additionally, while it works, it is not necessarily fast.

## Features

- **Asymmetric Encryption**: Uses RSA public/private key pairs for secure key exchange.
- **Symmetric Encryption**: Employs AES-256 in CTR mode for efficient data encryption.
- **Transparent Operation**: Integrates seamlessly with the filesystem, requiring no changes to user workflows.
- **Hidden Key Storage**: Stores encrypted symmetric keys and nonces securely using extended attributes and/or hidden key files.
- **Random Access**: Allows for random access to arbitrary parts of a file without decrypting the entire file.

## Tested Environment

- Ubuntu 22

## How It Works

### Encryption Mode (Write-Only)

1. **Symmetric Key Generation**: Generates a random AES-256 symmetric key and a 16-byte nonce for each file.
2. **File Encryption**: Encrypts file contents using the symmetric key and AES-256 in CTR mode.
3. **Key Encryption**: Encrypts the symmetric key with the RSA public key using OAEP padding.
4. **Key Storage**: Stores the encrypted symmetric key and nonce as extended attributes (`xattrs`) or in a hidden `.key` file.

### Decryption Mode (Read-Only)

1. **Key Retrieval**: Retrieves the encrypted symmetric key and nonce from `xattrs` or the hidden `.key` file.
2. **Key Decryption**: Decrypts the symmetric key using the RSA private key.
3. **File Decryption**: Decrypts the file contents using the symmetric key and AES-256 in CTR mode.
4. **Transparent Access**: Presents the decrypted file to the user without altering the original encrypted data.

## Purpose

The primary goal of AEFS is to provide a secure and transparent method for encrypting files on a point-in-time-trusted (ideally immutable) operating system using both asymmetric and symmetric cryptography. This allows for one-way encryption of files by simply booting the operating system and running AEFS without the private key being needed at time of encryption.

## Example Use Cases

- **Secure Data Backup**: Encrypt sensitive files before backing them up to untrusted storage locations.
- **Encrypted Drop Box**: Allow any user to securely encrypt a file, while restricting read access to only users with the private key.
- **Offline Photojournalism**: Keep sensitive data securely encrypted with an offsite-located strong private key that can not be brute forced like a password.
- **Disconnected IoT Devices**: Encrypt sensitive data on an IoT device where tampering can be detected but data at rest is required to stay encrypted.

## Weaknesses

While AEFS works well to quickly and easily encrypt data, it is required that the operating environment is trusted. For this reason, we recommend a tamper-proof or tamper-detectable operating system and/or machine. Ideally the operating system should be run offline and immutably on a verifiable read-only medium.

AEFS will provide very little protection against a sophisticated attacker that is able to modify this script (or any lower-level calls) to allow for a second static, symmetric key in addition to the randomly generated one. Nefarious changes to this script would natually allow potential access to all encrypted files.

AEFS implicitly trusts the environment it is running in and expects the user to have safeguards in place to protect that environment between every run. Additionally, if the environment is compromised and the user is made aware, AEFS ensures that their data was protected during the compromise but that a new safe environment needs to be created.

## Alternative Projects

Also consider [wocfs](https://www.arthy.org/wocfs/) which may offer similar functionality.

[age](https://github.com/FiloSottile/age) and [gpg](https://gnupg.org/) may also serve as better underlying cryptography libraries to be used with FUSE rather than the custom cryptography implemented here.

## Installation

### Prerequisites

- **Python 3.x**
- **FUSE 3**
- **Python Packages**:
  - `fusepy`
  - `cryptography`
  - `pyxattr`

### Install Dependencies

```bash
sudo apt update
sudo apt install python3 python3-pip libfuse-dev
sudo pip3 install fusepy cryptography pyxattr
```

## Usage

### Generate RSA Keys

```bash
# Generate a 2048-bit private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract the public key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

### Setup Directories

```bash
mkdir encrypted_dir  # Directory to store encrypted files
mkdir decrypted_dir  # Mount point for decrypted access
```

### Run in Encryption Mode

```bash
python3 aefs.py encrypted_dir decrypted_dir public_key.pem
```

- **Mode**: Write-Only
- **Operation**: Files written to `decrypted_dir` are encrypted and stored in `encrypted_dir`.

### Run in Decryption Mode

```bash
python3 aefs.py encrypted_dir decrypted_dir public_key.pem --private_key private_key.pem
```

- **Mode**: Read-Only
- **Operation**: Files in `encrypted_dir` are decrypted on-the-fly when accessed via `decrypted_dir`.
