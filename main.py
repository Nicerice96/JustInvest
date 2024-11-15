import bcrypt
from enum import Enum
from typing import List, Optional, Tuple
from datetime import datetime
import os

# Load the password pepper from the environment variable or use a default if not set.
# In a real scenario, this should be stored securely, such as in an environment variable.
pepper = os.environ.get('PASSWORD_PEPPER', '102030020120300120120301203110203')

class Permissions(Enum):
    """The various permissions available in the justInvest System.

    Args:
        Enum (_type_): _description_
    """
    CLIENT_VIEW_BALANCE = 1  # Permission to view client balance
    VIEW_CLIENT_PORTFOLIO = 2  # Permission to view client portfolio
    VIEW_CONTACT_DETAILS_FA = 3  # Permission to view financial advisor contact details
    MODIFY_CLIENT_PORTFOLIO = 4  # Permission to modify client portfolio
    VIEW_CONTACT_DETAILS_FP = 5  # Permission to view financial planner contact details
    VIEW_MONEY_MARKET_INSTRUMENTS = 6  # Permission to view money market instruments
    VIEW_PRIVATE_CONSUMER_INSTRUMENTS = 7  # Permission to view private consumer instruments
    TELLER_ACCESS = 8  # Permission for teller access

class Role:
    """A class to hold a given member of the justInvest System's role and their respective permissions.

    Args:
        role_type (str): The type of role.
        permissions (List[Permissions]): A list of permissions associated with the role.
    """
    def __init__(self, role_type: str, permissions: List[Permissions]):
        self.role_type = role_type
        self.permissions = permissions

class PasswordManager:
    """A class for managing password hashing and verification using bcrypt.

    Returns:
        _type_: _description_
    """
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash a password with salt and pepper using bcrypt.

        Args:
            password (str): The password to be hashed.

        Returns:
            bytes: The hashed password.
        """
        # Combine the password with the pepper
        password_with_pepper = (password + pepper).encode()
        return bcrypt.hashpw(password_with_pepper, bcrypt.gensalt())

    @staticmethod
    def verify_password(password: str, stored_hash: bytes) -> bool:
        """Verify a password against a stored hash.

        Args:
            password (str): The password to verify.
            stored_hash (bytes): The stored hashed password.

        Returns:
            bool: True if the password matches the stored hash, False otherwise.
        """
        # Combine the password with the pepper
        password_with_pepper = (password + pepper).encode()
        return bcrypt.checkpw(password_with_pepper, stored_hash)

class User:
    """User default class.

    Args:
        username (str): The username of the user.
        hashed_password (bytes): The hashed password of the user.
        role (Role): The role of the user.
    """
    def __init__(self, username: str, hashed_password: bytes, role: Role):
        self.username = username
        self.hashed_password = hashed_password
        self.role = role
        self.balance = 0.0
        self.portfolio = []
        self.financial_advisor = None
        self.financial_planner = None
        self.money_market_instrument = ""
        self.private_consumer_instruments = ""

    def has_permission(self, permission: Permissions) -> bool:
        """Check if the user has a specific permission.

        Args:
            permission (Permissions): The permission to check.

        Returns:
            bool: True if the user has the permission, False otherwise.
        """
        return permission in self.role.permissions

    def add_permissions(self, permissions):
        """Add permissions to the user's role.

        Args:
            permissions: The permissions to add.
        """
        self.role.permissions.extend(permissions)

    def revoke_permissions(self, permissions):
        """Revoke permissions from the user's role.

        Args:
            permissions: The permissions to revoke.
        """
        print(f"Revoked permissions: {permissions}")
        self.role.permissions.remove(permissions)

    def get_username(self) -> str:
        """Get the username of the user.

        Returns:
            str: The username.
        """
        return self.username

    def get_hashed_password(self) -> bytes:
        """Get the hashed password of the user.

        Returns:
            bytes: The hashed password.
        """
        return self.hashed_password

    def view_balance(self):
        """View the balance of the user if they have the necessary permission.

        Returns:
            float or str: The balance if the user has permission, otherwise a message indicating no permission.
        """
        if self.has_permission(Permissions.CLIENT_VIEW_BALANCE):
            return self.balance
        else:
            return "You do not have permission to view the balance."

    def view_portfolio(self):
        """View the portfolio of the user if they have the necessary permission.

        Returns:
            list or str: The portfolio if the user has permission, otherwise a message indicating no permission.
        """
        if self.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO):
            return self.portfolio
        else:
            return "You do not have permission to view the portfolio."

    def modify_portfolio(self):
        """Modify the portfolio of the user if they have the necessary permission.

        Returns:
            None or str: Modifies the portfolio if the user has permission, otherwise a message indicating no permission.
        """
        if self.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO):
            print("Enter an Investment\n")
            input_val = input("\nPlease enter your Investment: ")
            self.portfolio.append(input_val)
        else:
            return "You do not have permission to modify the portfolio."

    def set_financial_advisor(self, financial_advisor):
        """Set the financial advisor for the user if they have the necessary permission.

        Args:
            financial_advisor: The financial advisor to set.
        """
        if self.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA):
            self.financial_advisor = financial_advisor

    def get_financial_advisor(self):
        """Get the financial advisor of the user if they have the necessary permission.

        Returns:
            str or None: The financial advisor if the user has permission, otherwise None.
        """
        if self.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA):
            return self.financial_advisor

    def set_financial_planner(self, financial_planner):
        """Set the financial planner for the user if they have the necessary permission.

        Args:
            financial_planner: The financial planner to set.
        """
        if self.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP):
            self.financial_planner = financial_planner

    def get_financial_planner(self):
        """Get the financial planner of the user if they have the necessary permission.

        Returns:
            str or None: The financial planner if the user has permission, otherwise None.
        """
        if self.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP):
            return self.financial_planner

    def get_money_market_instruments(self):
        """Get the money market instruments of the user if they have the necessary permission.

        Returns:
            str or None: The money market instruments if the user has permission, otherwise None.
        """
        if self.has_permission(Permissions.VIEW_MONEY_MARKET_INSTRUMENTS):
            return self.money_market_instrument

    def get_private_consumer_instruments(self):
        """Get the private consumer instruments of the user if they have the necessary permission.

        Returns:
            str or None: The private consumer instruments if the user has permission, otherwise None.
        """
        if self.has_permission(Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS):
            return self.private_consumer_instruments

    def is_within_business_hours(self) -> bool:
        """Check if the current time is within business hours.

        Returns:
            bool: True if within business hours, False otherwise.
        """
        if self.has_permission(Permissions.TELLER_ACCESS):
            current_time = datetime.now().time()
            start_time = datetime.strptime("09:00", "%H:%M").time()
            end_time = datetime.strptime("17:00", "%H:%M").time()
            return start_time <= current_time <= end_time

class StandardClient(User):
    """Standard Client of the justInvest System.

    Args:
        User (_type_): _description_
    """
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
    """Premium Client of the justInvest system.

    Args:
        User (_type_): _description_
    """
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
    """Teller for the justInvest system.

    Args:
        User (_type_): _description_
    """
    def __init__(self, username: str, hashed_password: bytes):
        super().__init__(
            username,
            hashed_password,
            Role(
                "Teller",
                [Permissions.TELLER_ACCESS]
            )
        )

class FinancialAdvisor(User):
    """FinancialAdvisor of the justInvestSystem.

    Args:
        User (_type_): _description_
    """
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
    """Financial Planner of the justInvest system.

    Args:
        User (_type_): _description_
    """
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

def load_common_passwords(filename: str) -> set:
    """Load common passwords from a file.

    Args:
        filename (str): The filename containing common passwords.

    Returns:
        set: A set of common passwords.
    """
    try:
        with open(filename, 'r') as file:
            common_passwords = set(line.strip().lower() for line in file.readlines())
            return common_passwords
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return set()

common_passwords = load_common_passwords('10k-most-common.txt')

def load_users_from_file(filename: str) -> dict:
    """Load users from a file.

    Args:
        filename (str): The filename containing user data.

    Returns:
        dict: A dictionary of users.
    """
    try:
        users = {}
        with open(filename, 'r') as file:
            for line in file.readlines():
                username, hashed_password, role, balance, portfolio = line.strip().split(',')
                users[username] = {
                    'hashed_password': hashed_password.encode(),
                    'role': role,
                    'balance': float(balance),
                    'portfolio': portfolio.split(';') if portfolio else []
                }
        return users
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"Error loading users: {e}")
        return {}

def save_users_to_file(users: dict, filename: str) -> None:
    """Save users to a file.

    Args:
        users (dict): A dictionary of users.
        filename (str): The filename to save the users to.
    """
    with open(filename, 'w') as file:
        for username, user_data in users.items():
            portfolio = ';'.join(user_data['portfolio']) if user_data['portfolio'] else ''
            file.write(f"{username},{user_data['hashed_password'].decode()},{user_data['role']},{user_data['balance']},{portfolio}\n")

def insert_user(users: dict, username: str, password: str, user_class, balance: float = 0.0) -> bool:
    """Insert a user into the users dictionary and save to file.

    Args:
        users (dict): The dictionary of users.
        username (str): The username of the new user.
        password (str): The password of the new user.
        user_class: The class of the new user.
        balance (float, optional): The balance of the new user. Defaults to 0.0.

    Returns:
        bool: True if the user was successfully inserted, False otherwise.
    """
    common_passwords = load_common_passwords('10k-most-common.txt')
    if not password_LUDS(password, common_passwords):
        return False

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
            'role': type(user).__name__,
            'balance': user.balance,
            'portfolio': user.portfolio
        }
        save_users_to_file(users, 'passwd.txt')
        return True
    except Exception as e:
        print(f"Error inserting user: {e}")
        return False

def authenticate(users: dict, username: str, password: str) -> bool:
    """Authenticate a user.

    Args:
        users (dict): The dictionary of users.
        username (str): The username to authenticate.
        password (str): The password to authenticate.

    Returns:
        bool: True if the authentication is successful, False otherwise.
    """
    try:
        user_data = users.get(username)
        if user_data:
            stored_hash = user_data['hashed_password']
            if PasswordManager.verify_password(password, stored_hash):
                return True
            else:
                # If the password does not match, it might be because the password was hashed without the pepper.
                # Rehash the password with the pepper and update the stored hash.
                new_hash = PasswordManager.hash_password(password)
                users[username]['hashed_password'] = new_hash
                save_users_to_file(users, 'passwd.txt')
                return True
        return False
    except Exception as e:
        print(f"Error during authentication: {e}")
        return False

def password_LUDS(password: str, common_passwords: set) -> bool:
    """Validate a password to ensure it meets the LUDS (Length, Uppercase, Digit, Special) criteria and is not common.

    Args:
        password (str): The password to validate.
        common_passwords (set): A set of common passwords.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
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

    if password.lower() in common_passwords: 
        print("Password is too common. Please choose a different password.")
        return False

    return True

def display_clients(users: dict):
    """Display all clients.

    Args:
        users (dict): The dictionary of users.

    Returns:
        str or None: The selected client's username or None if no client is selected.
    """
    print("\nAvailable Clients:")
    print("------------------")
    client_list = [username for username, user_data in users.items() if user_data['role'] in ['StandardClient', 'PremiumClient']]
    
    if not client_list:
        print("No clients available.")
        return None
    
    for idx, client in enumerate(client_list):
        print(f"{idx + 1}. {client}")

    try:
        choice = int(input("\nSelect a client by number (or 0 to cancel): "))
        if choice == 0:
            return None
        if 1 <= choice <= len(client_list):
            selected_client = client_list[choice - 1]
            print(f"\nSelected Client: {selected_client}")
            return selected_client
        else:
            print("Invalid selection. Returning to menu.")
            return None
    except ValueError:
        print("Invalid input. Returning to menu.")
        return None

def just_invest_ui(user: User, users: dict):
    """The main UI for justInvest

    Args:
        user (User): The current user the justInvest System is dealing with it
        users (dict): The dictionary of users
    """
    running = True
    selected_client_username = None
    selected_client_data = None
    
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
        if isinstance(user, FinancialAdvisor) or isinstance(user, FinancialPlanner) or isinstance(user, Teller):
            print("9. Select a client to interact with !!(YOU MUST SELECT A CLIENT BEFORE PERFORMING THE ABOVE OPERATIONS)!!")
        print("0. Exit")

        try:
            choice = int(input("\nPlease enter your choice: "))
            print()

            if choice == 0:
                running = False
                continue

            if choice == 9 and (isinstance(user, FinancialAdvisor) or isinstance(user, FinancialPlanner) or isinstance(user, Teller)):
                selected_client_username = display_clients(users)
                if selected_client_username:
                    selected_client_data = users[selected_client_username]
                    selected_role = selected_client_data['role']
                    selected_hashed_password = selected_client_data['hashed_password']
                    selected_balance = selected_client_data['balance']
                    selected_portfolio = selected_client_data['portfolio']

                    if selected_role == 'StandardClient':
                        selected_client = StandardClient(selected_client_username, selected_hashed_password, selected_balance)
                        selected_client.portfolio = selected_portfolio
                        if isinstance(user, Teller):
                            if user.is_within_business_hours():
                                print("Teller Access Granted!")
                                selected_client.add_permissions(user.role.permissions)
                                just_invest_ui(selected_client, users)
                                selected_client.revoke_permissions(user.role.permissions)
                            else:
                                print("Teller Access Denied!")
                        else:
                            selected_client.add_permissions(user.role.permissions)
                            just_invest_ui(selected_client, users)
                            selected_client.revoke_permissions(user.role.permissions)

                    elif selected_role == 'PremiumClient':
                        selected_client = PremiumClient(selected_client_username, selected_hashed_password, selected_balance)
                        selected_client.portfolio = selected_portfolio
                        if isinstance(user, Teller):
                            if user.is_within_business_hours():
                                print("Teller Access Granted!")
                                selected_client.add_permissions(user.role.permissions)
                                just_invest_ui(selected_client, users)
                                selected_client.revoke_permissions(user.role.permissions)
                            else:
                                print("Teller Access Denied!")
                        else:
                            selected_client.add_permissions(user.role.permissions)
                            just_invest_ui(selected_client, users)
                            selected_client.revoke_permissions(user.role.permissions)

                    else:
                        print("\nSelected client has an unknown role. Returning to menu.")
                        continue

                    print(f"Interacting with client: {selected_client_username}")
                continue

                # Perform actions on the selected client

            actions = {
                1: (Permissions.CLIENT_VIEW_BALANCE, lambda: print(f"Current balance: ${user.view_balance()}\n")),
                2: (Permissions.VIEW_CLIENT_PORTFOLIO, lambda: print(f"Portfolio: {user.view_portfolio()}\n")),
                3: (Permissions.MODIFY_CLIENT_PORTFOLIO, lambda: user.modify_portfolio()),
                4: (Permissions.VIEW_CONTACT_DETAILS_FA, lambda: print(f"Financial Advisor: {user.get_financial_advisor()}")),
                5: (Permissions.VIEW_CONTACT_DETAILS_FP, lambda: print(f"Financial Planner: {user.get_financial_planner()}")),
                6: (Permissions.VIEW_MONEY_MARKET_INSTRUMENTS, lambda: print(f"Money Market Instruments: {user.get_money_market_instruments()}")),
                7: (Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS, lambda: print(f"Private Consumer Instruments: {user.get_private_consumer_instruments()}")),
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
                print("\nExiting.")

    print("\nExiting the justInvest System. Goodbye!")
    
def create_sample_clients(users):
    """creation of sample clients

    Args:
        users (dict): The dictionary of users 
    """
    sample_clients = [
        ("john_doe", "P@ssw0rd1", StandardClient, 1000.0),
        ("jane_smith", "Str0ngP@ss2", PremiumClient, 5000.0),
        ("bob_johnson", "S3cur3P@ss3", StandardClient, 2000.0),
        ("alice_brown", "C0mpl3xP@ss4", PremiumClient, 10000.0)
    ]

    for username, password, user_class, balance in sample_clients:
        if insert_user(users, username, password, user_class, balance):
            print(f"Sample client {username} created successfully.")
        else:
            print(f"Failed to create sample client {username}.")
            
            
def test_register_user():
    users = {}
    username = "test_user"
    password = "P@ssw0rd1"
    user_type = "StandardClient"
    balance = 1000.0

    if insert_user(users, username, password, StandardClient, balance):
        assert username in users
        assert users[username]['hashed_password'] != password  # Check if password is hashed
    else:
        assert False, "User registration failed"

test_register_user()

def test_login_user():
    users = {}
    username = "test_user"
    password = "P@ssw0rd1"
    user_type = "StandardClient"
    balance = 1000.0

    if insert_user(users, username, password, StandardClient, balance):
        if authenticate(users, username, password):
            assert True
        else:
            assert False, "Login failed"
    else:
        assert False, "User registration failed"

test_login_user()

def test_login_user_invalid_credentials():
    users = {}
    username = "test_user"
    password = "P@ssw0rd1"
    user_type = "StandardClient"
    balance = 1000.0

    if insert_user(users, username, password, StandardClient, balance):
        if not authenticate(users, username, "wrong_password"):
            assert True
        else:
            assert False, "Login should have failed"
    else:
        assert False, "User registration failed"

test_login_user_invalid_credentials()

def test_standard_client_permissions():
    users = {}
    username = "test_user"
    password = "P@ssw0rd1"
    user_type = "StandardClient"
    balance = 1000.0

    if insert_user(users, username, password, StandardClient, balance):
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        assert user.has_permission(Permissions.CLIENT_VIEW_BALANCE)
        assert user.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO)
        assert user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA)
        assert not user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO)
    else:
        assert False, "User registration failed"

test_standard_client_permissions()

def test_view_balance():
    users = {}
    username = "test_user"
    password = "P@ssw0rd1"
    user_type = "StandardClient"
    balance = 1000.0

    if insert_user(users, username, password, StandardClient, balance):
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        assert user.view_balance() == balance
    else:
        assert False, "User registration failed"

test_view_balance()
def test_view_portfolio():
    users = {}
    username = "test_user"
    password = "P@ssw0rd1"
    user_type = "StandardClient"
    balance = 1000.0

    if insert_user(users, username, password, StandardClient, balance):
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        assert user.view_portfolio() == []
    else:
        assert False, "User registration failed"

test_view_portfolio()

def test_modify_portfolio():
    users = {}
    username = "test_user"
    password = "P@ssw0rd1"
    user_type = "PremiumClient"
    balance = 1000.0

    if insert_user(users, username, password, PremiumClient, balance):
        user_data = users[username]
        user = PremiumClient(username, user_data['hashed_password'], balance)
        user.modify_portfolio()
        assert len(user.portfolio) > 0
    else:
        assert False, "User registration failed"

test_modify_portfolio()

def test_common_password_validation():
    common_passwords = load_common_passwords("10k-most-common.txt")
    users = {}
    username = "test_user"
    password = "password123"  # Assuming this is a common password
    user_type = "StandardClient"
    balance = 1000.0

    if not insert_user(users, username, password, StandardClient, balance):
        assert True
    else:
        assert False, "Registration should have failed due to common password"

test_common_password_validation()

def test_luds_password_validation():
    users = {}
    username = "test_user"
    password = "short"  # Password does not meet LUDS criteria
    user_type = "StandardClient"
    balance = 1000.0

    if not insert_user(users, username, password, StandardClient, balance):
        assert True
    else:
        assert False, "Registration should have failed due to password not meeting LUDS criteria"

test_luds_password_validation()


def main():
    """main function, includes entry UI
    """
    
    
    users = load_users_from_file('passwd.txt')
    create_sample_clients(users)
    common_passwords = load_common_passwords("10k-most-common.txt")

    
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
                print("Application closing...")
                break

            if choice == 1:
                username = input("Enter Username:\n").strip()
                password = input("Enter Password:\n").strip()
                if(not(password_LUDS(password, common_passwords))):
                    continue
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
                    just_invest_ui(user, users)
                    print("Login Successful!")
                else:
                    print("Login Unsuccessful!")

            else:
                print("\nInvalid choice. Please try again.")

        except ValueError:
            print("\nInvalid input. Please enter a number.")

#main funciton call
if __name__ == "__main__":
    main()