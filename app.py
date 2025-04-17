import os
import streamlit as st
import sqlite3
import hashlib
from cryptography.fernet import Fernet

# file create hogi
key_file = "simple_secret_key"

def load_key():
    # key nhi hogi to fernet.generate se ek key random generate hogi
    if not os.path.exists(key_file): 
        key= Fernet.generate_key()
        # random key write binary mode main open hogi
        with open(key_file,"wb") as f:
            # random key
            f.write(key)
    else:
        # agr key availablie ho gi to wo read mode main open hogi
        with open(key_file,"rb") as f:
            key = f.read()
            # or return ky through function se bhar ajaygi 
        return key
    # load_key() ke through jo key mili thi, usse cipher object create ho gaya.
cipher = Fernet(load_key())

    # Is function ka kaam hai SQLite database create karna aur ek table VAULT banwana.
def init_db():
    conn = sqlite3.connect("simple_data.db")
    c = conn.cursor()
    # Yeh table label, encrypted_text, aur passkey store karega.
    c.execute("""
        CREATE TABLE IF NOT EXISTS VAULT (
            label TEXT PRIMARY KEY,
            encrypted_text TEXT,
            passkey TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encryted(text):
    return cipher.encrypt(text.encode()).decode()

def decryted(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

st.title("🔒 Secure Data Encryption App")
menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.selectbox("Choose The Option", menu)

# Store Secret
if choice == "Store Secret":
    st.header("Store a New Secret")
    label = st.text_input("Label (Unique ID)")
    secret = st.text_area("Your Secret")
    passkey = st.text_input("PassKey (To Protect It)", type="password")

    if st.button("Encrypt & Save Key"):
        if label and secret and passkey:
            conn = sqlite3.connect("simple_data.db")
            c = conn.cursor()
            encrypted = encryted(secret)  # Encrypt the secret
            hashed_key = hash_passkey(passkey)  # Hash the passkey

            try:
                c.execute("INSERT INTO VAULT (label, encrypted_text, passkey) VALUES (?, ?, ?)", 
                          (label, encrypted, hashed_key))  # Insert into DB
                conn.commit()
                st.success("Secret Encrypted & Stored Successfully!")
            except sqlite3.IntegrityError:
                st.error("Label already exists. Please use a different one.")
            conn.close()


# Retrieve Secret
elif choice == "Retrieve Secret":
    st.header("Retrieve Your Secret")
    label = st.text_input("Enter Label")
    passkey = st.text_input("Enter PassKey", type="password")

    if st.button("Decrypt & Show"):
        if label and passkey:
            conn = sqlite3.connect("simple_data.db")
            c = conn.cursor()
            c.execute("SELECT encrypted_text, passkey FROM VAULT WHERE label = ?", (label,))
            result = c.fetchone()
            conn.close()

            if result:
                encrypted_text, stored_hash = result
                if hash_passkey(passkey) == stored_hash:
                    decrypted = decryted(encrypted_text)
                    st.success("Decrypted Secret:")
                    st.code(decrypted)
                else:
                    st.error("Incorrect PassKey!")
            else:
                st.error("Label not found!")
