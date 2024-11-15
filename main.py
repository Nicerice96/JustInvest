import bcrypt
import secrets
import re
from enum import Enum
from typing import List, Optional, Tuple
from datetime import datetime

# Define an Enum for user permissions
class Permissions(Enum):
    """Enum representing different user permissions."""
    CLIENT_VIEW_BALANCE = 1
    VIEW_CLIENT_PORTFOLIO = 2
    VIEW_CONTACT_DETAILS_FA = 3
    MODIFY_CLIENT_PORTFOLIO = 4
    VIEW_CONTACT_DETAILS_FP = 5
    VIEW_MONEY_MARKET_INSTRUMENTS = 6
    VIEW_PRIVATE_CONSUMER_INSTRUMENTS = 7
    TELLER_ACCESS = 8

# Define a class for user roles
class Role:
    """Class representing a user role with associated permissions."""
    def __init__(self, role_type: str, permissions: List[Permissions]):
        self.role_type = role_type
        self.permissions = permissions

# Define a class for managing passwords using bcrypt
class PasswordManager:
    """Class for hashing and verifying passwords using bcrypt."""
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash a password with a randomly generated salt using bcrypt."""
        # Convert the password to bytes and hash it with a generated salt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    @staticmethod
    def verify_password(password: str, stored_hash: bytes) -> bool:
        """Verify a password against a stored hash."""
        # Check if the provided password matches the stored hash
        return bcrypt.checkpw(password.encode(), stored_hash)

# Base class for users
class User:
    """Base class for users with common attributes and methods."""
    def __init__(self, username: str, hashed_password: bytes, role: Role):
        self.username = username
        self.hashed_password = hashed_password
        self.role = role
        self.balance = 0.0
        self.portfolio = []

    def has_permission(self, permission: Permissions) -> bool:
        """Check if the user has a specific permission."""
        return permission in self.role.permissions

    def get_username(self) -> str:
        """Get the username."""
        return self.username

    def get_hashed_password(self) -> bytes:
        """Get the hashed password."""
        return self.hashed_password

# Class for Standard Client users
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

# Class for Premium Client users
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

# Class for Teller users with additional business hours check
class Teller(User):
    """Class for Teller users with business hours restriction."""
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
        """Check if the current time is within business hours (9:00 AM to 5:00 PM)."""
        current_time = datetime.now().time()
        start_time = datetime.strptime("09:00", "%H:%M").time()
        end_time = datetime.strptime("17:00", "%H:%M").time()
        return start_time <= current_time <= end_time

    def has_permission(self, permission: Permissions) -> bool:
        """Check if the Teller has a specific permission, considering business hours."""
        if permission == Permissions.TELLER_ACCESS:
            if not self.is_within_business_hours():
                print("Access denied. Teller access is only allowed during business hours (9:00 AM to 5:00 PM).")
                return False
        return super().has_permission(permission)

# Class for Financial Advisor users
class FinancialAdvisor(User):
    """Class for Financial Advisor users."""
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

# Class for Financial Planner users
class FinancialPlanner(User):
    """Class for Financial Planner users."""
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

### Functions to Manage Password File

def load_users_from_file(filename: str) -> dict:
    """Load users from a file and return them as a dictionary."""
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
    """Save users to a file."""
    with open(filename, 'w') as file:
        for username, user_data in users.items():
            file.write(f"{username},{user_data['hashed_password'].decode()}, {user_data['role']}\n")

def insert_user(users: dict, username: str, password: str, user_class, balance: float = 0.0) -> bool:
    """
    Insert a new user into the users dictionary and save to file.

    :param users: Dictionary of existing users.
    :param username: Username of the new user.
    :param password: Password of the new user.
    :param user_class: Class of the new user (e.g., StandardClient, PremiumClient, etc.).
    :param balance: Initial balance for client users (default is 0.0).
    :return: True if the user is successfully created, False otherwise.
    """
    if password_LUDS(password, username):
        try:
            # Hash the password using bcrypt
            hashed_password = PasswordManager.hash_password(password)
            
            # Create a user instance with the hashed credentials
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
    """
    Authenticate a user by verifying their password.

    :param users: Dictionary of existing users.
    :param username: Username to authenticate.
    :param password: Password to verify.
    :return: True if the authentication is successful, False otherwise.
    """
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
    """
    Validate the password meets Length, Uppercase, Digit, Symbol requirements.

    :param password: Password to validate.
    :param username: Username associated with the password.
    :return: True if the password is valid, False otherwise.
    """
    if not (8 <= len(password) <= 72): # Adjusted to reflect bcrypt's 72 character limit[1][2][5]
        print("Password must be between 8 and 72 characters (inclusive).")
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

def just_invest_ui(user: User):
    """
    User interface for the justInvest system.

    :param user: User instance to manage the UI for.
    """
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

def main():
    """
    Main function to handle user registration and authentication.
    """
    users = load_users_from_file('passwd.txt')

    username = "testuser"
    password = "P@ssw0rd"
    user_type = "StandardClient"
    balance = 0.0

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

    # Reload users to ensure the newly added user is included
    users = load_users_from_file('passwd.txt')

    # Check if the user exists and verify the password
    if username in users:
        user_data = users[username]
        stored_hash = user_data['hashed_password']
        if PasswordManager.verify_password(password, stored_hash):
            print(f"User {username} retrieved and password verified successfully.")
        else:
            print(f"Password verification for user {username} failed.")
    else:
        print(f"User {username} not found in the passwd.txt file.")

if __name__ == "__main__":
    main()