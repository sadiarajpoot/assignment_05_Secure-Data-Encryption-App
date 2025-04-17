import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

# -------------------- Load or Create Key -------------------- #
key_file = "simple_secret_key"

def load_key():
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        with open(key_file, "rb") as f:
            key = f.read()
    return key

cipher = Fernet(load_key())

# -------------------- Initialize SQLite DB -------------------- #
def init_db():
    conn = sqlite3.connect("simple_data.db")
    c = conn.cursor()
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

# -------------------- Hash Function -------------------- #
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# -------------------- Encryption / Decryption -------------------- #
def encryted(text):
    return cipher.encrypt(text.encode()).decode()

def decryted(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# -------------------- Streamlit UI -------------------- #
st.title("🔒 Secure Data Encryption App")
menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.selectbox("Choose The Option", menu)

# Show the database absolute path for debugging
st.info(f"Database path: `{os.path.abspath('simple_data.db')}`")

if choice == "Store Secret":
    st.header("Store a New Secret")
    label = st.text_input("Label (Unique ID)")
    secret = st.text_area("Your Secret")
    passkey = st.text_input("PassKey (To Protect It)", type="password")

    if st.button("Encrypt & Save Key"):
        if label and secret and passkey:
            conn = sqlite3.connect("simple_data.db")
            c = conn.cursor()
            encrypted = encryted(secret)
            hashed_key = hash_passkey(passkey)

            try:
                c.execute("INSERT INTO VAULT (label, encrypted_text, passkey) VALUES (?, ?, ?)", 
                          (label, encrypted, hashed_key))
                conn.commit()
                st.success("Secret Encrypted & Stored Successfully!")

                # Fetch and show all stored data for debug
                c.execute("SELECT label FROM VAULT")
                all_rows = c.fetchall()
                st.info(f"Stored Labels: {[row[0] for row in all_rows]}")

            except sqlite3.IntegrityError:
                st.error("Label already exists. Please use a different one.")
            conn.close()

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
