import sqlite3
import hashlib
import secrets

# Function to create a new table in the database
def create_table():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, salt TEXT, hash TEXT)''')
    conn.commit()
    conn.close()

# Function to add a new user to the database
def add_user(username, password):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Generating a salt
    salt = secrets.token_hex(16)
    
    # Hashing the password with the salt
    hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    
    # Adding the user to the database
    c.execute("INSERT INTO users VALUES (?, ?, ?)", (username, salt, hashed_password))
    
    conn.commit()
    conn.close()

# Function to verify the password
def verify_password(username, password):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    
    # Retrieving the salt and hash from the database for the given user
    c.execute("SELECT salt, hash FROM users WHERE username=?", (username,))
    result = c.fetchone()
    
    if result:
        salt, hashed_password = result
        # Comparing the hashed password entered by the user with the stored hash
        if hashlib.sha256((password + salt).encode('utf-8')).hexdigest() == hashed_password:
            print("Correct password.")
        else:
            print("Incorrect password.")
    else:
        print("User does not exist.")
    
    conn.close()

# Example usage
if __name__ == "__main__":
    create_table()
    add_user("example_user", "example_password")
    verify_password("example_user", "example_password")
