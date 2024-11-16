import unittest
from main import *  # Import necessary modules and classes from the main file

class TestJustInvestSystem(unittest.TestCase):
    """
    This class contains unit tests for the JustInvest system, covering user registration, login, permissions, and other functionalities.
    """

    def test_register_user(self):
        """
        Test the registration of a new user.

        This test ensures that the `insert_user` function correctly adds a new user to the users dictionary, checks that the username is present, and verifies that the hashed password is different from the original password.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the new user.
            password (str): The password for the new user.
            user_type (class): The type of user (e.g., StandardClient).
            balance (float): The initial balance for the new user.
        """
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        self.assertTrue(insert_user(users, username, password, user_type, balance))
        self.assertIn(username, users)
        self.assertNotEqual(users[username]['hashed_password'], password)

    def test_login_user(self):
        """
        Test the login functionality for a valid user.

        This test ensures that the `authenticate` function correctly authenticates a user with valid credentials.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): The password for the user.
            user_type (class): The type of user (e.g., StandardClient).
            balance (float): The initial balance for the user.
        """
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        self.assertTrue(authenticate(users, username, password))

    def test_login_user_invalid_credentials(self):
        """
        Test the login functionality for a user with invalid credentials.

        This test ensures that the `authenticate` function correctly fails to authenticate a user with incorrect credentials.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): The password for the user.
            user_type (class): The type of user (e.g., StandardClient).
            balance (float): The initial balance for the user.
        """
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        self.assertFalse(authenticate(users, username, "wrong_password"))

    def test_standard_client_permissions(self):
        """
        Test the permissions of a StandardClient user.

        This test ensures that a StandardClient user has the correct permissions and does not have permissions that are exclusive to other user types.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): The password for the user.
            user_type (class): The type of user (e.g., StandardClient).
            balance (float): The initial balance for the user.
        """
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA))
        self.assertFalse(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))

    def test_premium_client_permissions(self):
        """
        Test the permissions of a PremiumClient user.

        This test ensures that a PremiumClient user has the correct permissions, including those exclusive to PremiumClient.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): The password for the user.
            user_type (class): The type of user (e.g., PremiumClient).
            balance (float): The initial balance for the user.
        """
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = PremiumClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = PremiumClient(username, user_data['hashed_password'], balance)
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))
        self.assertTrue(user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP))

    def test_view_balance(self):
        """
        Test the view balance functionality for a user.

        This test ensures that the `view_balance` method correctly returns the user's balance.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): The password for the user.
            user_type (class): The type of user (e.g., StandardClient).
            balance (float): The initial balance for the user.
        """
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        self.assertEqual(user.view_balance(), balance)

    def test_view_portfolio(self):
        """
        Test the view portfolio functionality for a user.

        This test ensures that the `view_portfolio` method correctly returns the user's portfolio, which should be empty initially.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): The password for the user.
            user_type (class): The type of user (e.g., StandardClient).
            balance (float): The initial balance for the user.
        """
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        self.assertEqual(user.view_portfolio(), [])

    def test_modify_portfolio(self):
        """
        Test the modify portfolio functionality for a PremiumClient user.

        This test simulates user input to modify the portfolio and ensures that the portfolio is updated correctly.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): The password for the user.
            user_type (class): The type of user (e.g., PremiumClient).
            balance (float): The initial balance for the user.
        """
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = PremiumClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = PremiumClient(username, user_data['hashed_password'], balance)
        # Simulate input for modify_portfolio
        import io
        import sys
        sys.stdin = io.StringIO("Test Investment\n")
        user.modify_portfolio()
        sys.stdin = sys.__stdin__  # Reset stdin
        self.assertGreater(len(user.portfolio), 0)

    def test_common_password_validation(self):
        """
        Test the validation of common passwords during user registration.

        This test ensures that the `insert_user` function correctly rejects common passwords.

        Parameters:
            common_passwords (list): A list of common passwords.
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): A common password.
            user_type (class): The type of user (e.g., StandardClient).
            balance (float): The initial balance for the user.
        """
        common_passwords = load_common_passwords("10k-most-common.txt")
        users = {}
        username = "test_user"
        password = "password123"  # Assuming this is a common password
        user_type = StandardClient
        balance = 1000.0

        self.assertFalse(insert_user(users, username, password, user_type, balance))

    def test_luds_password_validation(self):
        """
        Test the validation of passwords based on the LUDS (Length, Uppercase, Digit, Special character) criteria during user registration.

        This test ensures that the `insert_user` function correctly rejects passwords that do not meet the LUDS criteria.

        Parameters:
            users (dict): An empty dictionary to store user data.
            username (str): The username for the user.
            password (str): A password that does not meet LUDS criteria.
            user_type (class): The type of user (e.g., StandardClient).
            balance (float): The initial balance for the user.
        """
        users = {}
        username = "test_user"
        password = "short"  # Password does not meet LUDS criteria
        user_type = StandardClient
        balance = 1000.0

        self.assertFalse(insert_user(users, username, password, user_type, balance))

    def test_password_hashing(self):
        """
        Test the password hashing functionality.

        This test ensures that the `PasswordManager.hash_password` method correctly hashes the password and that the hashed password is different from the original password.

        Parameters:
            password (str): The password to be hashed.
        """
        password = "P@ssw0rd1"
        hashed_password = PasswordManager.hash_password(password)
        self.assertNotEqual(hashed_password, password)
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))

    def test_password_verification(self):
        """
        Test the password verification functionality.

        This test ensures that the `PasswordManager.verify_password` method correctly verifies a password against its hashed version and fails for an incorrect password.

        Parameters:
            password (str): The correct password.
            wrong_password (str): An incorrect password.
            hashed_password (bytes): The hashed version of the correct password.
        """
        password = "P@ssw0rd1"
        wrong_password = "WrongPassword"
        hashed_password = PasswordManager.hash_password(password)
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))
        self.assertFalse(PasswordManager.verify_password(wrong_password, hashed_password))

if __name__ == "__main__":
    unittest.main()