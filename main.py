import json
import hashlib
import secrets
import re
from enum import Enum
from typing import List, Optional, Tuple
from datetime import datetime

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

### Functions to Serialize and Deserialize Users
def serialize_user(user: User) -> dict:
    return {
        'username': user.username,
        'hashed_password': user.hashed_password.hex(),
        'salt': user.salt.hex(),
        'role': user.role.role_type,
        'permissions': [permission.name for permission in user.role.permissions],
        'balance': user.balance if hasattr(user, 'balance') else 0.0,
        'portfolio': user.portfolio if hasattr(user, 'portfolio') else [],
        'type': type(user).__name__
    }

def deserialize_user(serialized_user: dict) -> User:
    role_type = serialized_user['role']
    permissions = [Permissions[permission] for permission in serialized_user['permissions']]
    role = Role(role_type, permissions)

    if serialized_user['type'] == 'StandardClient':
        return StandardClient(
            serialized_user['username'],
            bytes.fromhex(serialized_user['hashed_password']),
            bytes.fromhex(serialized_user['salt']),
            balance=serialized_user['balance']
        )
    elif serialized_user['type'] == 'PremiumClient':
        return PremiumClient(
            serialized_user['username'],
            bytes.fromhex(serialized_user['hashed_password']),
            bytes.fromhex(serialized_user['salt']),
            balance=serialized_user['balance']
        )
    elif serialized_user['type'] == 'Teller':
        return Teller(
            serialized_user['username'],
            bytes.fromhex(serialized_user['hashed_password']),
            bytes.fromhex(serialized_user['salt'])
        )
    elif serialized_user['type'] == 'FinancialAdvisor':
        return FinancialAdvisor(
            serialized_user['username'],
            bytes.fromhex(serialized_user['hashed_password']),
            bytes.fromhex(serialized_user['salt'])
        )
    elif serialized_user['type'] == 'FinancialPlanner':
        return FinancialPlanner(
            serialized_user['username'],
            bytes.fromhex(serialized_user['hashed_password']),
            bytes.fromhex(serialized_user['salt'])
        )
    else:
        raise ValueError("Unknown user type")
    
    
def load_users_from_file(filename: str) -> dict:
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

def save_users_to_file(users: dict, filename: str) -> None:
    with open(filename, 'w') as file:
        json.dump(users, file, indent=4)
        
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


def insert_user(users: dict, username: str, password: str, user_class, balance: float = 0.0) -> bool:
    if password_LUDS(password, username):
        try:
            # Hash password with salt and pepper
            salt, hashed_password = PasswordManager.hash_password(password)
            
            # Create user instance with hashed credentials
            if user_class in (StandardClient, PremiumClient):
                user = user_class(username, hashed_password, salt, balance)
            else:
                user = user_class(username, hashed_password, salt)
            
            users[username] = serialize_user(user)
            save_users_to_file(users, 'users.json')
            return True
        except Exception as e:
            print(f"Error inserting user: {e}")
            return False
    return False

def authenticate(users: dict, username: str, password: str) -> bool:
    try:
        user_data = users.get(username)
        if user_data:
            stored_salt = bytes.fromhex(user_data['salt'])
            stored_hash = bytes.fromhex(user_data['hashed_password'])
            
            if PasswordManager.verify_password(password, stored_salt, stored_hash):
                user = deserialize_user(user_data)
                just_invest_ui(user)
                return True
        return False
    except Exception as e:
        print(f"Error during authentication: {e}")
        return False
    
    
def just_invest_ui(user: User):
    running = True
    while running:
        print("\njustInvest System:")
        print("-----------------------------")
        print(f"Operations Available to {user.get_username()}:")

        
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

def export_db_to_txt(users: dict, filename: str = "justInvest_backup.txt") -> bool:
    try:
        with open(filename, 'w') as f:
            f.write("JustInvest Database Backup\n")
            f.write("========================\n\n")
            
            for username, user_data in users.items():
                user = deserialize_user(user_data)
                f.write(f"Username: {username}\n")
                f.write(f"Role: {user.role.role_type}\n")
                f.write(f"Permissions: \n")
                for permission in user.role.permissions:
                    f.write(f"  - {permission.name}\n")
                if hasattr(user, 'balance'):
                    f.write(f"Balance: ${user.balance:.2f}\n")
                if hasattr(user, 'portfolio'):
                    f.write(f"Portfolio Items: {len(user.portfolio)}\n")
                f.write("\n" + "-"*50 + "\n\n")
                
        print(f"Database successfully exported to {filename}")
        return True
        
    except IOError as e:
        print(f"File error during export: {e}")
        return False
    except Exception as e:
        print(f"Error during export: {e}")
        return False
    
    
def main():
    users = load_users_from_file('users.json')
    
    while True:
        print("\njustInvest System:")
        print("-----------------------------")
        print("1. Register")
        print("2. Login")
        print("3. Export Database")
        print("0. Exit")

        try:
            choice = int(input("\nPlease enter your choice: "))
            print()

            if choice == 0:
                break

            if choice == 1:
                username = input("Enter Username:\n").strip()
                password = input("Enter Password:\n").strip()
                user_type = input("Enter User Type (StandardClient, PremiumClient, Teller, FinancialAdvisor, FinancialPlanner):\n").strip()
                balance = float(input("Enter Balance (if applicable):\n").strip()) if user_type in ['StandardClient', 'PremiumClient'] else 0.0

                user_classes = {
                    'StandardClient': StandardClient,
                    'PremiumClient': PremiumClient,
                    'Teller': Teller,
                    'FinancialAdvisor': FinancialAdvisor,
                    'FinancialPlanner': FinancialPlanner
                }

                if user_type in user_classes:
                    if insert_user(users, username, password, user_classes[user_type], balance):
                        print("User successfully created!")
                else:
                    print("Invalid user type.")

            elif choice == 2:
                username = input("Enter Username:\n").strip()
                password = input("Enter Password:\n").strip()

                if authenticate(users, username, password):
                    print("Login Successful!")
                else:
                    print("Login Unsuccessful!")

            elif choice == 3:
                export_db_to_txt(users)

            else:
                print("\nInvalid choice. Please try again.")

        except ValueError:
            print("\nInvalid input. Please enter a number.")

if __name__ == "__main__":
    main()