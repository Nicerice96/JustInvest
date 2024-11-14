import secrets
import hashlib
from enum import Enum
from typing import List, Optional, Tuple
from datetime import datetime

class Permissions(Enum):
    VIEW_BALANCE = 1
    DEPOSIT = 2
    WITHDRAW = 3
    MODIFY_ACCOUNT = 4
    CLOSE_ACCOUNT = 5

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
        self.account_number = self.generate_account_number()

    def has_permission(self, permission: Permissions) -> bool:
        return permission in self.role.permissions

    def get_username(self) -> str:
        return self.username

    def get_hashed_password(self) -> bytes:
        return self.hashed_password
        
    def get_salt(self) -> bytes:
        return self.salt

    def generate_account_number(self) -> str:
        return str(secrets.randbelow(99999 - 10000 + 1) + 10000)

    def deposit(self, amount: float):
        if amount > 0:
            self.balance += amount
            print(f"Deposited ${amount:.2f}. New balance: ${self.balance:.2f}")
        else:
            print("Amount must be greater than zero.")

    def withdraw(self, amount: float):
        if 0 < amount <= self.balance:
            self.balance -= amount
            print(f"Withdrew ${amount:.2f}. New balance: ${self.balance:.2f}")
        elif amount > self.balance:
            print("Insufficient funds.")
        else:
            print("Amount must be greater than zero.")

    def check_balance(self):
        print(f"Current balance: ${self.balance:.2f}")

class StandardUser(User):
    def __init__(self, username: str, hashed_password: bytes, salt: bytes, balance: float = 0.0):
        super().__init__(
            username,
            hashed_password,
            salt,
            Role(
                "StandardUser",
                [
                    Permissions.VIEW_BALANCE,
                    Permissions.DEPOSIT,
                    Permissions.WITHDRAW,
                    Permissions.MODIFY_ACCOUNT
                ]
            )
        )
        self.balance = balance

class AdminUser(User):
    def __init__(self, username: str, hashed_password: bytes, salt: bytes):
        super().__init__(
            username,
            hashed_password,
            salt,
            Role(
                "AdminUser",
                [
                    Permissions.VIEW_BALANCE,
                    Permissions.DEPOSIT,
                    Permissions.WITHDRAW,
                    Permissions.MODIFY_ACCOUNT,
                    Permissions.CLOSE_ACCOUNT
                ]
            )
        )

def write_user_to_file(filename: str, user: User):
    with open(filename, 'a') as f:
        f.write(f"Username: {user.get_username()}\n")
        f.write(f"Salt: {user.get_salt().hex()}\n")
        f.write(f"Hashed Password: {user.get_hashed_password().hex()}\n")
        f.write(f"Role: {user.role.role_type}\n")
        f.write(f"Account Number: {user.account_number}\n")
        f.write(f"Balance: ${user.balance:.2f}\n\n")

def read_users_from_file(filename: str) -> dict:
    users = {}
    with open(filename, 'r') as f:
        lines = f.readlines()
        user_data = []
        for line in lines:
            user_data.append(line.strip())
            if line.strip() == "":
                username = None
                salt = None
                hashed_password = None
                role_type = None
                account_number = None
                balance = 0.0
                for data in user_data:
                    if data.startswith("Username:"):
                        username = data.split(":")[1].strip()
                    elif data.startswith("Salt:"):
                        salt = bytes.fromhex(data.split(":")[1].strip())
                    elif data.startswith("Hashed Password:"):
                        hashed_password = bytes.fromhex(data.split(":")[1].strip())
                    elif data.startswith("Role:"):
                        role_type = data.split(":")[1].strip()
                    elif data.startswith("Account Number:"):
                        account_number = data.split(":")[1].strip()
                    elif data.startswith("Balance:"):
                        balance = float(data.split(":")[1].strip().replace("$", ""))
                if role_type == "StandardUser":
                    user = StandardUser(username, hashed_password, salt, balance)
                elif role_type == "AdminUser":
                    user = AdminUser(username, hashed_password, salt)
                user.account_number = account_number
                users[username] = user
                user_data = []
    return users

def insert_user_to_file(filename: str, username: str, password: str, user_class, balance: float = 0.0) -> bool:
    if password_LUDS(password, username):
        try:
            # Hash password with salt and pepper
            salt, hashed_password = PasswordManager.hash_password(password)
            
            # Create user instance with hashed credentials
            if user_class in (StandardUser,):
                user = user_class(username, hashed_password, salt, balance)
            else:
                user = user_class(username, hashed_password, salt)
            
            write_user_to_file(filename, user)
            return True
        except Exception as e:
            print(f"Error inserting user: {e}")
            return False
    return False

def authenticate_from_file(filename: str, username: str, password: str) -> User:
    users = read_users_from_file(filename)
    if username in users:
        user = users[username]
        if PasswordManager.verify_password(password, user.get_salt(), user.get_hashed_password()):
            return user
    return None

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

def banking_ui(user: User):
    running = True
    while running:
        print("\nBanking System:")
        print("------------------")
        print(f"Operations Available to {user.get_username()}:")
        
        if user.has_permission(Permissions.VIEW_BALANCE):
            print("1. View account balance")
        if user.has_permission(Permissions.DEPOSIT):
            print("2. Deposit money")
        if user.has_permission(Permissions.WITHDRAW):
            print("3. Withdraw money")
        if user.has_permission(Permissions.MODIFY_ACCOUNT):
            print("4. Modify account details")
        if user.has_permission(Permissions.CLOSE_ACCOUNT):
            print("5. Close account")
        print("0. Exit")

        try:
            choice = int(input("\nPlease enter your choice: "))
            print()

            if choice == 0:
                running = False
                continue

            # Define actions with deferred execution
            actions = {
                1: (Permissions.VIEW_BALANCE, lambda: user.check_balance()),
                2: (Permissions.DEPOSIT, lambda: user.deposit(float(input("Enter amount to deposit: ")))),
                3: (Permissions.WITHDRAW, lambda: user.withdraw(float(input("Enter amount to withdraw: ")))),
                4: (Permissions.MODIFY_ACCOUNT, lambda: modify_account(user)),
                5: (Permissions.CLOSE_ACCOUNT, lambda: close_account(user))
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

    print("\nExiting the banking system. Goodbye!")

def modify_account(user: User):
    print("Account Number : ", user.account_number)
    user.username = input("Modify Username : ")
    print("Note: Password cannot be modified here.")
    print("Role and Account Number are immutable.")

def close_account(user: User):
    print(f"Account {user.account_number} will be closed.")
    # Implement logic to remove the user from the file or mark as closed
    print("Account closed successfully.")

def main():
    filename = "banking_users.txt"
    
    username_create = "Zarif"
    password_create = "7GUBFKBu!"

    if insert_user_to_file(filename, username_create, password_create, StandardUser, balance=1000.0):
        print("User successfully created!")
        
    # Add more test users if you want
    insert_user_to_file(filename, "admin1", "Admin1@123", AdminUser)

    print("\nHello Welcome to the banking system.")
    username = input("Enter Username:\n").strip()
    password = input("Enter Password:\n").strip()

    user = authenticate_from_file(filename, username, password)
    if user:
        print("Login Successful!")
        banking_ui(user)
    else:
        print("Login Unsuccessful!")

if __name__ == "__main__":
    main()