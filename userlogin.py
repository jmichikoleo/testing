import streamlit as st
import sqlite3
import bcrypt
import os

# Database setup
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                  (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)''')
conn.commit()

# Hashing
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Regis
def register_user(username, email, password):
    hashed = hash_password(password)
    cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                   (username, email, hashed))
    conn.commit()

# Login
def login_user(email, password):
    cursor.execute('SELECT password FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    if result and verify_password(password, result[0]):
        return True
    return False

# Email valid
def validate_email(email):
    return email.endswith("@ks.ac.kr")

# File upload dir
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Streamlit UI
st.title("Login and Start your journey with Odyssey")

menu = ["Login", "Register"]
choice = st.sidebar.selectbox("Menu", menu)

# Login and Register Logic
if choice == "Login":
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if validate_email(email):
            if login_user(email, password):
                # Store user info in session state
                st.session_state["user"] = email.split('@')[0]
                st.success(f"Welcome back, {st.session_state['user']}!")
            else:
                st.error("Invalid email or password")
        else:
            st.error("Only emails with '@ks.ac.kr' are allowed.")

elif choice == "Register":
    st.subheader("Register")
    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Register"):
        if validate_email(email):
            if password == confirm_password:
                register_user(username, email, password)
                st.success("Account created successfully!")
            else:
                st.error("Passwords do not match.")
        else:
            st.error("Only emails with '@ks.ac.kr' are allowed.")

# File upload system
if "user" in st.session_state:
    st.subheader(f"Welcome, {st.session_state['user']}!")
    
    # File upload UI
    uploaded_file = st.file_uploader("Upload a PDF file", type=["pdf"])

    if uploaded_file:
        file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success(f"File '{uploaded_file.name}' uploaded successfully!")

    # Display uploaded files
    st.subheader("Uploaded Files")
    uploaded_files = os.listdir(UPLOAD_DIR)

    if uploaded_files:
        for file_name in uploaded_files:
            file_path = os.path.join(UPLOAD_DIR, file_name)
            st.write(f"File Name: {file_name}")
            with open(file_path, "rb") as file_data:
                st.download_button(label=f"Download {file_name}", data=file_data, file_name=file_name, mime="application/pdf")
    else:
        st.info("No files uploaded yet.")

else:
    st.warning("Please log in to access the file upload system.")

# Close DB
import atexit
atexit.register(conn.close)
