import bcrypt
import secrets
import re
from enum import Enum
from typing import List, Optional, Tuple
from datetime import datetime
import os

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
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash a password with salt using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    @staticmethod
    def verify_password(password: str, stored_hash: bytes) -> bool:
        """Verify a password against stored hash."""
        return bcrypt.checkpw(password.encode(), stored_hash)

class User:
    def __init__(self, username: str, hashed_password: bytes, role: Role):
        self.username = username
        self.hashed_password = hashed_password
        self.role = role
        self.balance = 0.0
        self.portfolio = []
        self.financial_advisor = None

    def has_permission(self, permission: Permissions) -> bool:
        return permission in self.role.permissions

    def get_username(self) -> str:
        return self.username

    def get_hashed_password(self) -> bytes:
        return self.hashed_password
    
    def view_portfolio(self):
        if self.has_permission(Permissions.CLIENT_VIEW_BALANCE):
            return self.portfolio
        else:
            return "You do not have permission to view the portfolio."

    def modify_portfolio(self):
        if self.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO):
            print("Enter an Investment\n")
            input_val = input("\nPlease enter your Investment: ")
            self.portfolio.append(input_val)
        else:
            return "You do not have permission to modify the portfolio."
        
    def set_financial_advisor(self, financial_advisor):
        if(self.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA)):
            self.financial_advisor = financial_advisor

    def get_financial_advisor(self):
        if(self.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA)):
            return self.financial_advisor

class StandardClient(User):
    def __init__(self, username: str, hashed_password: bytes, balance: float = 0.0):
        super().__init__(
            username,
            hashed_password,
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
    def __init__(self, username: str, hashed_password: bytes, balance: float = 0.0):
        super().__init__(
            username,
            hashed_password,
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
    def __init__(self, username: str, hashed_password: bytes):
        super().__init__(
            username,
            hashed_password,
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
    def __init__(self, username: str, hashed_password: bytes):
        super().__init__(
            username,
            hashed_password,
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
    def __init__(self, username: str, hashed_password: bytes):
        super().__init__(
            username,
            hashed_password,
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

def load_users_from_file(filename: str) -> dict:
    try:
        users = {}
        with open(filename, 'r') as file:
            for line in file.readlines():
                username, hashed_password, role = line.strip().split(',')
                users[username] = {
                    'hashed_password': hashed_password.encode(),
                    'role': role
                }
        return users
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"Error loading users: {e}")
        return {}

def save_users_to_file(users: dict, filename: str) -> None:
    with open(filename, 'w') as file:
        for username, user_data in users.items():
            file.write(f"{username},{user_data['hashed_password'].decode()}, {user_data['role']}\n")

def insert_user(users: dict, username: str, password: str, user_class, balance: float = 0.0) -> bool:
    if password_LUDS(password, username):
        try:
            # Hash password using bcrypt
            hashed_password = PasswordManager.hash_password(password)
            
            # Create user instance with hashed credentials
            if user_class in (StandardClient, PremiumClient):
                user = user_class(username, hashed_password, balance)
            else:
                user = user_class(username, hashed_password)
            
            users[username] = {
                'hashed_password': hashed_password,
                'role': type(user).__name__
            }
            save_users_to_file(users, 'passwd.txt')
            return True
        except Exception as e:
            print(f"Error inserting user: {e}")
            return False
    return False

def authenticate(users: dict, username: str, password: str) -> bool:
    try:
        user_data = users.get(username)
        if user_data:
            stored_hash = user_data['hashed_password']
            if PasswordManager.verify_password(password, stored_hash):
                return True
        return False
    except Exception as e:
        print(f"Error during authentication: {e}")
        return False

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
        return False
    if not has_lower:
        print("Password must contain at least one lowercase letter.")
        return False
    if not has_digit:
        print("Password must contain at least one digit.")
        return False
    if not has_special:
        print("Password must contain at least one symbol.")
        return False

    return True

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

            actions = {
                1: (Permissions.CLIENT_VIEW_BALANCE, lambda: print(f"\nCurrent balance: ${user.balance:.2f}\n")),
                2: (Permissions.VIEW_CLIENT_PORTFOLIO, lambda: print(user.view_portfolio())),
                3: (Permissions.MODIFY_CLIENT_PORTFOLIO, lambda: print(user.modify_portfolio())),
                4: (Permissions.VIEW_CONTACT_DETAILS_FA, lambda: print(user.get_financial_advisor())),
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

def main():
    users = load_users_from_file('passwd.txt')
    
    while True:
        print("\njustInvest System:")
        print("-----------------------------")
        print("1. Register")
        print("2. Login")
        print("0. Exit")

        try:
            choice = int(input("\nPlease enter your choice: "))
            print()

            if choice == 0:
                os.remove("passwd.txt")
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
                    user_data = users[username]
                    role_type = user_data['role']
                    if role_type == 'StandardClient':
                        user = StandardClient(username, user_data['hashed_password'])
                    elif role_type == 'PremiumClient':
                        user = PremiumClient(username, user_data['hashed_password'])
                    elif role_type == 'Teller':
                        user = Teller(username, user_data['hashed_password'])
                    elif role_type == 'FinancialAdvisor':
                        user = FinancialAdvisor(username, user_data['hashed_password'])
                    elif role_type == 'FinancialPlanner':
                        user = FinancialPlanner(username, user_data['hashed_password'])
                    else:
                        print("Invalid user type")
                    just_invest_ui(user)
                    print("Login Successful!")
                else:
                    print("Login Unsuccessful!")

            else:
                print("\nInvalid choice. Please try again.")

        except ValueError:
            print("\nInvalid input. Please enter a number.")

if __name__ == "__main__":
    main()