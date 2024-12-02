import sqlite3
import csv
import hashlib
from cryptography.fernet import Fernet

# Generate and save the encryption key securely
encryption_key = Fernet.generate_key()
key_string = encryption_key.decode('utf-8')
with open("secure_key.key", "w") as key_file:
    key_file.write(key_string)
cipher = Fernet(encryption_key)

# SQLite database file
database_file = "healthcare_system.db"

# Establish connection to SQLite
conn = sqlite3.connect(database_file)
cursor = conn.cursor()

# Create table for healthcare records with encrypted columns
cursor.execute("""
CREATE TABLE IF NOT EXISTS patient_records (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT,
    last_name TEXT,
    encrypted_gender TEXT,    -- Encrypted gender
    encrypted_age TEXT,       -- Encrypted age
    weight REAL,
    height REAL,
    medical_history TEXT,
    integrity_hash TEXT
)
""")

# Create table for admin accounts
cursor.execute("""
CREATE TABLE IF NOT EXISTS admin_accounts (
    username TEXT PRIMARY KEY,
    hashed_password TEXT,  -- SHA-256 hashed password
    access_level TEXT      -- 'A' for Admin, 'R' for Read-Only
)
""")

# Function to create a row hash
def compute_row_integrity(data_tuple):
    concatenated_data = "|".join(str(item) for item in data_tuple)
    return hashlib.sha256(concatenated_data.encode()).hexdigest()

# Function to hash passwords
def create_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to encrypt sensitive data
def secure_encrypt(value):
    return cipher.encrypt(str(value).encode()).decode()

# Load data from CSV file
csv_file_name = "patient_data.csv"
with open(csv_file_name, "r") as csv_file:
    csv_reader = csv.DictReader(csv_file)
    healthcare_data = []

    for row in csv_reader:
        # Encrypt sensitive fields
        gender_encrypted = secure_encrypt(row["Gender"])
        age_encrypted = secure_encrypt(row["Age"])

        # Prepare row for insertion (hash non-sensitive fields only)
        row_details = (
            row["First Name"],
            row["Last Name"],
            gender_encrypted,
            age_encrypted,
            float(row["Weight"]),
            float(row["Height"]),
            row["Health History"]
        )

        # Generate a unique hash for data integrity
        integrity_hash = compute_row_integrity((row["First Name"], row["Last Name"], row["Weight"], row["Height"], row["Health History"]))

        # Add full row to data list
        healthcare_data.append(row_details + (integrity_hash,))

# Insert healthcare data into the database
insert_healthcare_query = """
INSERT INTO patient_records (
    first_name, last_name, encrypted_gender, encrypted_age, weight, height, medical_history, integrity_hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""
cursor.executemany(insert_healthcare_query, healthcare_data)

# Add admin users to the admin_accounts table
admin_users = [
    ("superadmin", create_password_hash("adminSecure123"), "H"),  # Full access admin
    ("readuser1", create_password_hash("readonly123"), "R"),     # Restricted access
    ("readuser2", create_password_hash("passRead456"), "R")      # Restricted access
]

insert_admin_query = """
INSERT INTO admin_accounts (username, hashed_password, access_level)
VALUES (?, ?, ?)
"""
cursor.executemany(insert_admin_query, admin_users)

# Commit changes and close connection
conn.commit()
cursor.close()
conn.close()

# Notify user about successful operation
print(f"Encryption key has been saved to 'secure_key.key'. Please store it securely.")
print(f"Data from '{csv_file_name}' has been inserted into SQLite database '{database_file}' with encrypted sensitive fields and integrity hashes.")
print("Admin accounts have also been added successfully.")

