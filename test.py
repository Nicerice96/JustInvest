import unittest
from main import *

class TestJustInvestSystem(unittest.TestCase):

    # Test the registration of a new user
    def test_register_user(self):
        # Initialize an empty users dictionary
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        # Test if the user is successfully inserted
        self.assertTrue(insert_user(users, username, password, user_type, balance))
        # Test if the username is in the users dictionary
        self.assertIn(username, users)
        # Test if the password is hashed correctly
        self.assertNotEqual(users[username]['hashed_password'], password)

    # Test the login functionality with valid credentials
    def test_login_user(self):
        # Initialize an empty users dictionary
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        # Insert the user into the users dictionary
        insert_user(users, username, password, user_type, balance)
        # Test if the authentication is successful
        self.assertTrue(authenticate(users, username, password))

    # Test the login functionality with invalid credentials
    def test_login_user_invalid_credentials(self):
        # Initialize an empty users dictionary
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        # Insert the user into the users dictionary
        insert_user(users, username, password, user_type, balance)
        # Test if the authentication fails with wrong password
        self.assertFalse(authenticate(users, username, "wrong_password"))

    # Test permissions for a standard client
    def test_standard_client_permissions(self):
        # Initialize an empty users dictionary
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        # Insert the user into the users dictionary
        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        
        # Test various permissions for the standard client
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA))
        self.assertFalse(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))

    # Test permissions for a premium client
    def test_premium_client_permissions(self):
        # Initialize an empty users dictionary
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = PremiumClient
        balance = 1000.0

        # Insert the user into the users dictionary
        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = PremiumClient(username, user_data['hashed_password'], balance)
        
        # Test various permissions for the premium client
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))
        self.assertTrue(user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP))

    # Test viewing the balance of a user
    def test_view_balance(self):
        # Initialize an empty users dictionary
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        # Insert the user into the users dictionary
        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        
        # Test if the balance is correctly displayed
        self.assertEqual(user.view_balance(), balance)

    # Test viewing the portfolio of a user
    def test_view_portfolio(self):
        # Initialize an empty users dictionary
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        # Insert the user into the users dictionary
        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)
        
        # Test if the portfolio is correctly displayed (initially empty)
        self.assertEqual(user.view_portfolio(), [])

    # Test modifying the portfolio of a premium user
    def test_modify_portfolio(self):
        # Initialize an empty users dictionary
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = PremiumClient
        balance = 1000.0

        # Insert the user into the users dictionary
        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = PremiumClient(username, user_data['hashed_password'], balance)
        
        # Simulate input for modifying the portfolio
        import io
        import sys
        sys.stdin = io.StringIO("Test Investment\n")
        user.modify_portfolio()
        sys.stdin = sys.__stdin__  # Reset stdin
        
        # Test if the portfolio has been modified
        self.assertGreater(len(user.portfolio), 0)

    # Test password validation against common passwords
    def test_common_password_validation(self):
        common_passwords = load_common_passwords("10k-most-common.txt")
        users = {}
        username = "test_user"
        password = "password123"  # Assuming this is a common password
        user_type = StandardClient
        balance = 1000.0

        # Test if inserting a common password fails
        self.assertFalse(insert_user(users, username, password, user_type, balance))

    # Test password validation against LUDS criteria
    def test_luds_password_validation(self):
        users = {}
        username = "test_user"
        password = "short"  # Password does not meet LUDS criteria
        user_type = StandardClient
        balance = 1000.0

        # Test if inserting a password that does not meet LUDS criteria fails
        self.assertFalse(insert_user(users, username, password, user_type, balance))

    # Test password hashing and verification
    def test_password_hashing(self):
        password = "P@ssw0rd1"
        hashed_password = PasswordManager.hash_password(password)
        
        # Test if the hashed password is different from the original
        self.assertNotEqual(hashed_password, password)
        # Test if the password verification is successful
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))

    # Test password verification with correct and incorrect passwords
    def test_password_verification(self):
        password = "P@ssw0rd1"
        wrong_password = "WrongPassword"
        hashed_password = PasswordManager.hash_password(password)
        
        # Test if the correct password is verified successfully
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))
        # Test if the wrong password is not verified
        self.assertFalse(PasswordManager.verify_password(wrong_password, hashed_password))

if __name__ == "__main__":
    unittest.main()