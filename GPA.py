import streamlit as st
import sqlite3
import hashlib
from PIL import Image
import os

# SQLite Database setup
conn = sqlite3.connect('graphical_password_auth.db', check_same_thread=False)
c = conn.cursor()

# Create a users table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT, email TEXT, password TEXT)''')
conn.commit()

# Function to hash the password
def hash_password(symbols):
    password = ''.join(symbols)  # Combine symbols selected
    return hashlib.sha256(password.encode()).hexdigest()

# Function to register a new user
def register_user(username, email, password_hash):
    c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
              (username, email, password_hash))
    conn.commit()

# Function to check login
def verify_user(username, password_hash):
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
              (username, password_hash))
    return c.fetchone()

# Function to retrieve all users
def get_all_users():
    c.execute('SELECT username, email, password FROM users')
    return c.fetchall()

# Load symbol images
def load_symbols(size=(100, 100)):  # Set desired size here
    symbols = []
    symbol_files = sorted(os.listdir('symbols'))  # Ensure symbols are sorted
    for symbol_file in symbol_files:
        img = Image.open(f"symbols/{symbol_file}")
        img = img.resize(size)  # Resize the image to the specified size
        symbols.append(img)
    return symbols, symbol_files

# Symbol selection
def symbol_selection():
    st.write("Select your graphical password:")
    symbols, symbol_files = load_symbols()
    selected_symbols = []
    
    columns = st.columns(4)
    for i, img in enumerate(symbols):
        with columns[i % 4]:
            st.image(img, use_column_width=True)
            if st.checkbox(f"Select Symbol {i}", key=f"symbol_{i}"):
                selected_symbols.append(symbol_files[i])
    return selected_symbols

# Admin Login
def admin_login():
    st.subheader("Admin Login")
    admin_password = st.text_input("Admin Password", type='password')

    if st.button("Login"):
        if admin_password == "Welcome@123":  # Change this to your desired admin password
            st.session_state.admin_logged_in = True
            st.success("Login successful!")
        else:
            st.error("Invalid password!")

# Admin Dashboard
def admin_dashboard():
    st.subheader("User Details")
    users = get_all_users()
    
    if users:
        # Create a DataFrame for better visualization
        import pandas as pd
        user_data = pd.DataFrame(users, columns=["Username", "Email", "Password Hash"])
        st.dataframe(user_data)  # Display the DataFrame as a table
    else:
        st.write("No users found.")

# Function to show successful login message
def successful_login_page(username):
    st.title("Login Successful")
    st.success(f"Welcome back, {username}!")

# Function to inject custom CSS for the background
def set_background(page):
    if page == "🏠 Home":
        bg_url = "url('https://static.vecteezy.com/system/resources/thumbnails/023/339/353/small/minimalistic-fluid-blurred-gradient-background-trendy-neon-backdrop-for-poster-brochure-banner-landing-page-and-night-club-vector.jpg')"  # Change to your image URL
    elif page == "🔑 Login":
        bg_url = "url('https://static.vecteezy.com/system/resources/thumbnails/023/339/353/small/minimalistic-fluid-blurred-gradient-background-trendy-neon-backdrop-for-poster-brochure-banner-landing-page-and-night-club-vector.jpg')"  # Change to your image URL
    elif page == "📝 Register":
        bg_url = "url('https://static.vecteezy.com/system/resources/thumbnails/023/339/353/small/minimalistic-fluid-blurred-gradient-background-trendy-neon-backdrop-for-poster-brochure-banner-landing-page-and-night-club-vector.jpg')"  # Change to your image URL
    elif page == "👨‍💻 Admin":
        bg_url = "url('https://static.vecteezy.com/system/resources/thumbnails/023/339/353/small/minimalistic-fluid-blurred-gradient-background-trendy-neon-backdrop-for-poster-brochure-banner-landing-page-and-night-club-vector.jpg')"  # Change to your image URL
    
    st.markdown(f"""
        <style>
        .stApp {{
            background-image: {bg_url};
            background-size: cover;
        }}
        </style>
        """, unsafe_allow_html=True)

# Main application
def main():
    st.title("Graphical Password Authentication")

    # Add icons to menu items using emoji shortcodes
    menu = [
        "🏠 Home",       # House icon
        "🔑 Login",      # Key icon
        "📝 Register",   # Memo icon
        "👨‍💻 Admin"     # Laptop with man icon (for admin)
    ]
    
    choice = st.sidebar.selectbox("Menu", menu)

    # Set background based on selected page
    set_background(choice)

    if choice == "🏠 Home":
        st.subheader("Welcome to Graphical Password Authentication System")

    elif choice == "🔑 Login":
        st.subheader("Login to your account")

        username = st.text_input("Username")
        selected_symbols = symbol_selection()

        if st.button("Login"):
            if len(selected_symbols) >= 4:
                hashed_password = hash_password(selected_symbols)
                result = verify_user(username, hashed_password)
                if result:
                    # Redirect to the successful login page
                    successful_login_page(username)
                else:
                    st.error("Invalid username or password!")
            else:
                st.error("Please select at least 4 symbols for your graphical password.")

    elif choice == "📝 Register":
        st.subheader("Create a new account")
        
        username = st.text_input("Username")
        email = st.text_input("Email")
        
        selected_symbols = symbol_selection()

        if st.button("Register"):
            if len(selected_symbols) >= 4:
                hashed_password = hash_password(selected_symbols)
                register_user(username, email, hashed_password)
                st.success("Account created successfully! You can now log in.")
            else:
                st.error("Please select at least 4 symbols for your graphical password.")
    
    elif choice == "👨‍💻 Admin":
        if 'admin_logged_in' not in st.session_state:
            admin_login()
        else:
            admin_dashboard()

if __name__ == "__main__":
    # Create folder for symbol images if it doesn't exist
    os.makedirs('symbols', exist_ok=True)

    # Ensure symbol images are available
    if not all(os.path.exists(f'symbols/symbol_{i}.png') for i in range(16)):
        st.error("Please make sure you have 16 symbol images in the 'symbols' folder.")

    # Run the Streamlit app
    main()