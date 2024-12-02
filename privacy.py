import sqlite3
import hashlib
from cryptography.fernet import Fernet
import os

# Read the encryption key (ensure this is stored securely)
with open("secure_key.key", 'r') as key_file:
    encryption_key = key_file.read().strip()

cipher = Fernet(encryption_key)

# Path to SQLite database file
database_file = "healthcare_system.db"

# Function to securely hash passwords
def generate_hash(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

def secure_encrypt(value):
    return cipher.encrypt(str(value).encode()).decode()

# Function to decrypt encrypted data
def decode_data(encrypted_string):
    return cipher.decrypt(encrypted_string.encode()).decode()

# Function to create a row identifier hash
def compute_row_hash(row_data):
    concatenated_data = "|".join(str(field) for field in row_data)
    return hashlib.sha256(concatenated_data.encode()).hexdigest()

# Function to verify data integrity
def validate_data_integrity(db_cursor):
    db_cursor.execute("SELECT * FROM patient_records")
    rows = db_cursor.fetchall()
    for row in rows:
        row_hash = compute_row_hash((row[1], row[2], row[5], row[6], row[7]))
        if row_hash != row[8]:
            print(f"Data integrity issue detected in record ID: {row[0]}")
            exit()

def remove_extra_data(data):
    al = data.replace("\"", "")
    a2 = a1.replace(" ", "")
    a3 = a2.replace(")", "")
    a4 = a3.replace("(","")
    return a4

# Function to manage database queries based on user permissions
def query_interface(user_role):
    conn = sqlite3.connect(database_file)
    db_cursor = conn.cursor()
    
    while True:
        print("\n--- Query Console ---")
        command = input("Enter an SQL command (type 'exit' to log out): ").strip()

        if command.lower() == "exit":
            print("Logging out...")
            break

        if command.strip().lower().startswith("select"):
            if user_role == "R":
                if "first_name" in command.lower() or "last_name" in command.lower():
                    print("Permission Denied: Access to 'first_name' or 'last_name' is restricted.")
                    continue

                command = command.replace("*", "encrypted_gender, encrypted_age, weight, height, medical_history ")

            try:
                
                db_cursor.execute(command)
                results = db_cursor.fetchall()
                #print(results)
                validate_data_integrity(db_cursor)
                
                for record in results:
                    if len(record) == 9:
                        dd = record[:-1]
                    else:
                        dd = record

                    for field in dd:
                        try:
                            print(" ", decode_data(field), end="")
                        except:
                            print(" ", field, end="")
                    print()
            except sqlite3.Error as error:
                print(f"Database Error: {error}")
        elif command.strip().lower().startswith("insert"):
            if user_role == "R":
                print("Error: You do not have permission to run non-SELECT queries (INSERT, UPDATE, DELETE).")
                continue
            else:
                command_split = command.lower().split("values")
                command_item = command_split[1].split(",")
                first_name = remove_extra_data(command_item[0])
                last_name = remove_extra_data(command_item[1])
                gender = remove_extra_data(command_item[2])
                age = remove_extra_data(command_item[3])
                weight = remove_extra_data(command_item[4])
                height = remove_extra_data(command_item[5])
                health_history = remove_extra_data(command_item[6])
                encrypted_gender = secure_encrypt(gender)
                encrypted_age = secure_encrypt(age)
                hash_value = compute_row_hash((first_name, last_name, weight, height, health_history))
                data_filter = command_split[0].replace(")","")
                new_query = data_filter+", integrity_hash) values ('"+first_name+"', '"+last_name+"', '"+str(encrypted_gender)+"', '"+str(encrypted_age)+"', "+str(weight)+", "+str(height)+", '"+health_history+"', '"+hash_value+"')"
                try:
                    db_cursor.execute(new_query)
                    conn.commit()
                    print(f"Record inserted successfully, ID: {db_cursor.lastrowid}")
                except sqlite3.Error as err:
                    print(f"Error: {err}")
    conn.close()

# Function to handle user login
def user_authentication():
    conn = sqlite3.connect(database_file)
    db_cursor = conn.cursor()
    print("\n--- Login ---")
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    db_cursor.execute("SELECT username, hashed_password, access_level FROM admin_accounts WHERE username = ?", (username,))
    user_record = db_cursor.fetchone()

    if not user_record or generate_hash(password) != user_record[1]:
        print("Invalid login credentials.")
        conn.close()
        return None

    print(f"Login Successful! Welcome, {user_record[0]} (Role: {user_record[2]})")
    conn.close()
    return user_record

# Function to register new users
def register_user():
    conn = sqlite3.connect(database_file)
    db_cursor = conn.cursor()
    print("\n--- User Registration ---")
    username = input("Choose a username: ").strip()
    password = input("Set a password: ").strip()
    role = input("Specify role (H for Admin, R for Read-Only): ").strip().upper()

    if role not in ["H", "R"]:
        print("Invalid role. Choose 'H' or 'R'.")
        conn.close()
        return

    db_cursor.execute("SELECT * FROM admin_accounts WHERE username = ?", (username,))
    if db_cursor.fetchone():
        print("Username already taken. Please choose another.")
        conn.close()
        return

    hashed_password = generate_hash(password)
    db_cursor.execute("INSERT INTO admin_accounts (username, hashed_password, access_level) VALUES (?, ?, ?)", 
                      (username, hashed_password, role))
    conn.commit()
    conn.close()
    print("Registration Successful! You may now log in.")

# Main menu function
def application_menu():
    while True:
        print("\n--- Main Menu ---")
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            user_data = user_authentication()
            if user_data:
                _, _, user_role = user_data
                query_interface(user_role)
        elif choice == "2":
            register_user()
        elif choice == "3":
            print("Goodbye!")
            exit()
        else:
            print("Invalid selection. Please choose 1, 2, or 3.")

# Entry point for the script
if __name__ == "__main__":
    if not os.path.exists(database_file):
        print(f"Database file '{database_file}' does not exist. Ensure it is created before running.")
    else:
        application_menu()

