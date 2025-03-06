from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import streamlit as st
import base64
import time
import hashlib
import datetime
import json

# Key files
AES_KEY_FILE = "aes_key.key"
RSA_PRIVATE_KEY_FILE = "rsa_private.pem"
RSA_PUBLIC_KEY_FILE = "rsa_public.pem"
LOG_FILE = "encryption_log.json"

# Generate AES key
if not os.path.exists(AES_KEY_FILE):
    aes_key = os.urandom(32)
    with open(AES_KEY_FILE, "wb") as key_file:
        key_file.write(aes_key)

# Generate RSA key pair
if not os.path.exists(RSA_PRIVATE_KEY_FILE):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open(RSA_PRIVATE_KEY_FILE, "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(RSA_PUBLIC_KEY_FILE, "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Load keys
def load_aes_key():
    with open(AES_KEY_FILE, "rb") as key_file:
        return key_file.read()

def load_rsa_keys():
    with open(RSA_PRIVATE_KEY_FILE, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(priv_file.read(), password=None)
    with open(RSA_PUBLIC_KEY_FILE, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())
    return private_key, public_key

def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = data.ljust((len(data) + 15) // 16 * 16)
    encrypted_data = encryptor.update(padded_data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_aes(data, key):
    raw_data = base64.b64decode(data)
    iv, encrypted_data = raw_data[:16], raw_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data).decode().strip()

def log_activity(action, details):
    log_entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "details": details
    }
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r+") as log_file:
            logs = json.load(log_file)
            logs.append(log_entry)
            log_file.seek(0)
            json.dump(logs, log_file, indent=4)
    else:
        with open(LOG_FILE, "w") as log_file:
            json.dump([log_entry], log_file, indent=4)

# Streamlit UI
st.set_page_config(page_title="CodeSecure - Secure Messaging & File Sharing", layout="wide")
st.title("🔐 CodeSecure - Advanced Encryption")

st.sidebar.header("Secure Communication")

aes_key = load_aes_key()
private_key, public_key = load_rsa_keys()

# Secure Messaging Section
st.subheader("📩 Secure Messaging")
message_input = st.text_area("Enter message to encrypt:")
if st.button("Encrypt Message"):
    with st.spinner("Encrypting..."):
        time.sleep(1)
        encrypted_msg = encrypt_aes(message_input, aes_key)
        log_activity("Message Encrypted", encrypted_msg)
        st.text_area("Encrypted Message", encrypted_msg)

message_decrypt_input = st.text_area("Enter encrypted message to decrypt:")
if st.button("Decrypt Message"):
    try:
        with st.spinner("Decrypting..."):
            time.sleep(1)
            decrypted_msg = decrypt_aes(message_decrypt_input, aes_key)
            st.text_area("Decrypted Message", decrypted_msg)
    except Exception as e:
        st.error("Invalid encryption format.")

# Secure File Encryption
st.subheader("📂 Secure File Encryption")
file_to_encrypt = st.file_uploader("Upload file to encrypt", type=["txt", "pdf", "png", "jpg", "docx"])
if file_to_encrypt:
    with st.spinner("Encrypting file..."):
        time.sleep(1)
        file_contents = file_to_encrypt.read()
        encrypted_file_content = encrypt_aes(file_contents.decode('latin1'), aes_key)
        log_activity("File Encrypted", file_to_encrypt.name)
        st.download_button("Download Encrypted File", encrypted_file_content, file_name="secure_file.enc")

decrypt_file = st.file_uploader("Upload encrypted file to decrypt", type=["enc"])
if decrypt_file:
    with st.spinner("Decrypting file..."):
        time.sleep(1)
        decrypted_contents = decrypt_aes(decrypt_file.read().decode('latin1'), aes_key)
        st.download_button("Download Decrypted File", decrypted_contents, file_name="decrypted_file.txt")
