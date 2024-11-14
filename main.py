import sqlite3
import pickle
from enum import Enum
from typing import List, Optional, Tuple
from datetime import datetime
import hashlib
import secrets
import re

class Permissions(Enum):
    CLIENT_VIEW_BALANCE = 1
    VIEW_CLIENT_PORTFOLIO = 2
    VIEW_CONTACT_DETAILS_FA = 3
    MODIFY_CLIENT_PORTFOLIO = 4
    VIEW_CONTACT_DETAILS_FP = 5
    VIEW_MONEY_MARKET_INSTRUMENTS = 6
    VIEW_PRIVATE_CONSUMER_INSTRUMENTS = 7
    TELLER_ACCESS = 8

class Role:
    def __init__(self, role_type: str, permissions: List[Permissions]):
        self.role_type = role_type
        self.permissions = permissions

class PasswordManager:
    PEPPER = b"your_secure_pepper_value_here"
    
    @staticmethod
    def hash_password(password: str) -> Tuple[bytes, bytes]:
        """Hash a password with salt and pepper.
        Returns: (salt, hashed_password)"""
        salt = secrets.token_bytes(32)
        salted_peppered = password.encode() + salt + PasswordManager.PEPPER
        hashed = hashlib.sha256(salted_peppered).digest()
        return salt, hashed
    
    @staticmethod
    def verify_password(password: str, stored_salt: bytes, stored_hash: bytes) -> bool:
        """Verify a password against stored salt and hash"""
        salted_peppered = password.encode() + stored_salt + PasswordManager.PEPPER
        hashed = hashlib.sha256(salted_peppered).digest()
        return secrets.compare_digest(hashed, stored_hash)

class User:
    def __init__(self, username: str, hashed_password: bytes, salt: bytes, role: Role):
        self.username = username
        self.hashed_password = hashed_password
        self.salt = salt
        self.role = role
        self.balance = 0.0
        self.portfolio = []

    def has_permission(self, permission: Permissions) -> bool:
        return permission in self.role.permissions

    def get_username(self) -> str:
        return self.username

    def get_hashed_password(self) -> bytes:
        return self.hashed_password
        
    def get_salt(self) -> bytes:
        return self.salt

class StandardClient(User):
    def __init__(self, username: str, hashed_password: bytes, salt: bytes, balance: float = 0.0):
        super().__init__(
            username,
            hashed_password,
            salt,
            Role(
                "StandardClient",
                [
                    Permissions.CLIENT_VIEW_BALANCE,
                    Permissions.VIEW_CLIENT_PORTFOLIO,
                    Permissions.VIEW_CONTACT_DETAILS_FA
                ]
            )
        )
        self.balance = balance

class PremiumClient(User):
    def __init__(self, username: str, hashed_password: bytes, salt: bytes, balance: float = 0.0):
        super().__init__(
            username,
            hashed_password,
            salt,
            Role(
                "PremiumClient",
                [
                    Permissions.CLIENT_VIEW_BALANCE,
                    Permissions.VIEW_CLIENT_PORTFOLIO,
                    Permissions.MODIFY_CLIENT_PORTFOLIO,
                    Permissions.VIEW_CONTACT_DETAILS_FP
                ]
            )
        )
        self.balance = balance

class Teller(User):
    def __init__(self, username: str, hashed_password: bytes, salt: bytes):
        super().__init__(
            username,
            hashed_password,
            salt,
            Role(
                "Teller",
                [Permissions.TELLER_ACCESS]
            )
        )

    def is_within_business_hours(self) -> bool:
        current_time = datetime.now().time()
        start_time = datetime.strptime("09:00", "%H:%M").time()
        end_time = datetime.strptime("17:00", "%H:%M").time()
        return start_time <= current_time <= end_time

    def has_permission(self, permission: Permissions) -> bool:
        if permission == Permissions.TELLER_ACCESS:
            if not self.is_within_business_hours():
                print("Access denied. Teller access is only allowed during business hours (9:00am to 5:00pm).")
                return False
        return super().has_permission(permission)

class FinancialAdvisor(User):
    def __init__(self, username: str, hashed_password: bytes, salt: bytes):
        super().__init__(
            username,
            hashed_password,
            salt,
            Role(
                "FinancialAdvisor",
                [
                    Permissions.CLIENT_VIEW_BALANCE,
                    Permissions.VIEW_CLIENT_PORTFOLIO,
                    Permissions.MODIFY_CLIENT_PORTFOLIO,
                    Permissions.VIEW_CONTACT_DETAILS_FA,
                    Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS
                ]
            )
        )

class FinancialPlanner(User):
    def __init__(self, username: str, hashed_password: bytes, salt: bytes):
        super().__init__(
            username,
            hashed_password,
            salt,
            Role(
                "FinancialPlanner",
                [
                    Permissions.CLIENT_VIEW_BALANCE,
                    Permissions.VIEW_CLIENT_PORTFOLIO,
                    Permissions.MODIFY_CLIENT_PORTFOLIO,
                    Permissions.VIEW_CONTACT_DETAILS_FP,
                    Permissions.VIEW_MONEY_MARKET_INSTRUMENTS,
                    Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS
                ]
            )
        )

def serialize_user(user: User) -> bytes:
    return pickle.dumps(user)

def deserialize_user(serialized_user: bytes) -> User:
    return pickle.loads(serialized_user)

def password_LUDS(password: str, username: str) -> bool:
    """Validate password meets Length, Uppercase, Digit, Symbol requirements"""
    if not (8 <= len(password) <= 12):
        print("Password must be between 8 and 12 characters (inclusive).")
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if not has_upper:
        print("Password must contain at least one uppercase letter.")
    if not has_lower:
        print("Password must contain at least one lowercase letter.")
    if not has_digit:
        print("Password must contain at least one digit.")
    if not has_special:
        print("Password must contain at least one symbol.")

    print(f"Password validation results: UpperCase: {has_upper}, LowerCase: {has_lower}, "
          f"Digit: {has_digit}, Special: {has_special}")

    return all([has_upper, has_lower, has_digit, has_special])

def create_database() -> Optional[sqlite3.Connection]:
    try:
        db = sqlite3.connect("justInvest.db")
        return db
    except sqlite3.Error as e:
        print(f"Error opening database: {e}")
        return None

def create_table(db: sqlite3.Connection) -> bool:
    try:
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                hashed_password BLOB NOT NULL,
                serialized_user BLOB NOT NULL
            )
        """)
        db.commit()
        return True
    except sqlite3.Error as e:
        print(f"Error in creating table: {e}")
        return False

def insert_user(db: sqlite3.Connection, username: str, password: str, user_class, balance: float = 0.0) -> bool:
    if password_LUDS(password, username):
        try:
            # Hash password with salt and pepper
            salt, hashed_password = PasswordManager.hash_password(password)
            
            # Create user instance with hashed credentials
            if user_class in (StandardClient, PremiumClient):
                user = user_class(username, hashed_password, salt, balance)
            else:
                user = user_class(username, hashed_password, salt)
            
            cursor = db.cursor()
            serialized_user = serialize_user(user)
            
            cursor.execute(
                "INSERT INTO Users (username, salt, hashed_password, serialized_user) VALUES (?, ?, ?, ?)",
                (username, salt, hashed_password, serialized_user)
            )
            db.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error inserting user: {e}")
            return False
    return False

def just_invest_ui(user: User):
    running = True
    while running:
        print("\njustInvest System:")
        print("-----------------------------")
        print(f"Operations Available to {user.get_username()}:")

        # Display options based on permissions
        if user.has_permission(Permissions.CLIENT_VIEW_BALANCE):
            print("1. View account balance")
        if user.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO):
            print("2. View investment portfolio")
        if user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO):
            print("3. Modify investment portfolio")
        if user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA):
            print("4. View Financial Advisor contact details")
        if user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP):
            print("5. View Financial Planner contact details")
        if user.has_permission(Permissions.VIEW_MONEY_MARKET_INSTRUMENTS):
            print("6. View money market instruments")
        if user.has_permission(Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS):
            print("7. View private consumer instruments")
        if user.has_permission(Permissions.TELLER_ACCESS):
            print("8. Teller-specific options")
        print("0. Exit")

        try:
            choice = int(input("\nPlease enter your choice: "))
            print()

            if choice == 0:
                running = False
                continue

            # Define actions with deferred execution
            actions = {
                1: (Permissions.CLIENT_VIEW_BALANCE, lambda: print(f"\nCurrent balance: ${user.balance:.2f}\n")),
                2: (Permissions.VIEW_CLIENT_PORTFOLIO, lambda: print("\nViewing portfolio...\n")),
                3: (Permissions.MODIFY_CLIENT_PORTFOLIO, lambda: print("\nModifying investment portfolio...\n")),
                4: (Permissions.VIEW_CONTACT_DETAILS_FA, lambda: print("\nViewing Financial Advisor contact details...\n")),
                5: (Permissions.VIEW_CONTACT_DETAILS_FP, lambda: print("\nViewing Financial Planner contact details...\n")),
                6: (Permissions.VIEW_MONEY_MARKET_INSTRUMENTS, lambda: print("\nViewing money market instruments...\n")),
                7: (Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS, lambda: print("\nViewing private consumer instruments...\n")),
                8: (Permissions.TELLER_ACCESS, lambda: print("\nAccessing Teller-specific options...\n"))
            }

            if choice in actions:
                permission, action = actions[choice]
                if user.has_permission(permission):
                    action()
                else:
                    print("\nYou do not have permission for this action.")
            else:
                print("\nInvalid choice. Please try again.")

        except ValueError:
            print("\nInvalid input. Please enter a number.")

    print("\nExiting the justInvest System. Goodbye!")

def authenticate(db: sqlite3.Connection, username: str, password: str) -> bool:
    try:
        cursor = db.cursor()
        cursor.execute(
            "SELECT salt, hashed_password, serialized_user FROM Users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()
        
        if result:
            stored_salt = result[0]
            stored_hash = result[1]
            
            if PasswordManager.verify_password(password, stored_salt, stored_hash):
                user = deserialize_user(result[2])
                just_invest_ui(user)
                return True
        return False
    except sqlite3.Error as e:
        print(f"Error during authentication: {e}")
        return False

def main():
    db = create_database()
    if not db:
        return

    if not create_table(db):
        db.close()
        return

    # Example user creation
    username_create = "Zarif"
    password_create = "7GUBFKBu!"

    if insert_user(db, username_create, password_create, StandardClient, balance=1000.0):
        print("User successfully created!")

    print("\nHello! Welcome to justInvest.")
    username = input("Enter Username:\n").strip()
    password = input("Enter Password:\n").strip()

    if authenticate(db, username, password):
        print("Login Successful!")
    else:
        print("Login Unsuccessful!")

    db.close()

if __name__ == "__main__":
    main()