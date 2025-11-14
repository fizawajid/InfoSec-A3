"""
Database operations for SecureChat system
Handles user registration and authentication
"""
import mysql.connector
from mysql.connector import Error
import os
import hashlib
import secrets

class Database:
    def __init__(self, host='localhost', database='securechat', 
                 user='root', password=''):
        """Initialize database connection"""
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.connection = None
    
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password
            )
            if self.connection.is_connected():
                print("[DB] Connected to MySQL database")
                return True
        except Error as e:
            print(f"[DB ERROR] Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("[DB] Disconnected from database")
    
    def register_user(self, email, username, password):
        """
        Register a new user with salted password hash
        Returns: (success: bool, message: str)
        """
        try:
            cursor = self.connection.cursor()
            
            # Check if user already exists
            cursor.execute(
                "SELECT id FROM users WHERE email = %s OR username = %s",
                (email, username)
            )
            if cursor.fetchone():
                return False, "User already exists"
            
            # Generate random 16-byte salt
            salt = secrets.token_bytes(16)
            
            # Compute salted hash: SHA256(salt || password)
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            
            # Insert user
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
            self.connection.commit()
            cursor.close()
            
            print(f"[DB] User registered: {username}")
            return True, "Registration successful"
            
        except Error as e:
            print(f"[DB ERROR] Registration failed: {e}")
            return False, str(e)
    
    def authenticate_user(self, email, password):
        """
        Authenticate user with email and password
        Returns: (success: bool, username: str or None)
        """
        try:
            cursor = self.connection.cursor()
            
            # Fetch user's salt and stored hash
            cursor.execute(
                "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                return False, None
            
            username, salt, stored_hash = result
            
            # Recompute hash with provided password
            computed_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            
            # Constant-time comparison to prevent timing attacks
            if secrets.compare_digest(computed_hash, stored_hash):
                # Update last login
                cursor = self.connection.cursor()
                cursor.execute(
                    "UPDATE users SET last_login = NOW() WHERE email = %s",
                    (email,)
                )
                self.connection.commit()
                cursor.close()
                
                print(f"[DB] User authenticated: {username}")
                return True, username
            else:
                return False, None
                
        except Error as e:
            print(f"[DB ERROR] Authentication failed: {e}")
            return False, None

# Example usage
if __name__ == "__main__":
    # Test database connection
    db = Database(user='root', password='your_mysql_password')
    if db.connect():
        # Test registration
        success, msg = db.register_user('alice@test.com', 'alice', 'SecurePass123')
        print(f"Registration: {msg}")
        
        # Test authentication
        success, username = db.authenticate_user('alice@test.com', 'SecurePass123')
        if success:
            print(f"Login successful for {username}")
        else:
            print("Login failed")
        
        db.disconnect()
