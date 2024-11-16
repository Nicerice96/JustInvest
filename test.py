import unittest
from freezegun import freeze_time
import datetime
from main import PasswordManager, User, Role, Permissions, StandardClient, PremiumClient, Teller, FinancialAdvisor, FinancialPlanner
from main import insert_user, authenticate, load_users_from_file, save_users_to_file, password_LUDS

class TestPasswordManager(unittest.TestCase):
    """
    This class contains test cases for the PasswordManager and related user functionalities.
    """

    def test_hash_password(self):
        """
        Test the hashing of a password.
        """
        password = "P@ssw0rd"
        hashed_password = PasswordManager.hash_password(password)
        # Check if the hashed password is of type bytes and longer than the original password
        self.assertIsInstance(hashed_password, bytes)
        self.assertGreater(len(hashed_password), len(password.encode()))

    def test_verify_password(self):
        """
        Test the verification of a password against its hashed version.
        """
        password = "P@ssw0rd"
        hashed_password = PasswordManager.hash_password(password)
        # Verify the correct password
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))
        # Verify an incorrect password
        self.assertFalse(PasswordManager.verify_password("WrongPassword", hashed_password))

    def test_password_LUDS(self):
        """
        Test the password validation function (Length, Uppercase, Digits, Special characters).
        """
        # Test a valid password
        password = "P@ssw0rd"
        self.assertTrue(password_LUDS(password, "testuser"))

        # Test a password that is too short
        password = "P@ss"
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test a password that is too long
        password = "P@ssw0rd" * 10
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test a password missing uppercase
        password = "p@ssw0rd"
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test a password missing lowercase
        password = "P@SSW0RD"
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test a password missing digits
        password = "P@ssword"
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test a password missing special characters
        password = "Passw0rd"
        self.assertFalse(password_LUDS(password, "testuser"))

    def test_insert_user(self):
        """
        Test the insertion of a new user into the users dictionary.
        """
        users = {}
        username = "testuser"
        password = "P@ssw0rd"
        user_type = StandardClient
        balance = 0.0

        # Insert the user and check if the operation was successful
        self.assertTrue(insert_user(users, username, password, user_type, balance))
        # Check if the user is in the users dictionary
        self.assertIn(username, users)

    def test_authenticate_user(self):
        """
        Test the authentication of a user.
        """
        users = {}
        username = "testuser"
        password = "P@ssw0rd"
        user_type = StandardClient
        balance = 0.0

        # Insert the user
        insert_user(users, username, password, user_type, balance)
        # Authenticate with the correct password
        self.assertTrue(authenticate(users, username, password))
        # Authenticate with an incorrect password
        self.assertFalse(authenticate(users, username, "WrongPassword"))

    def test_load_and_save_users(self):
        """
        Test loading and saving users from/to a file.
        """
        users = {}
        username = "testuser"
        password = "P@ssw0rd"
        user_type = StandardClient
        balance = 0.0

        # Insert the user
        insert_user(users, username, password, user_type, balance)
        # Save the users to a file
        save_users_to_file(users, 'passwd.txt')
        # Load the users from the file
        loaded_users = load_users_from_file('passwd.txt')
        # Check if the user is in the loaded users
        self.assertIn(username, loaded_users)

    def test_user_roles_and_permissions(self):
        """
        Test the roles and permissions of a user.
        """
        username = "testuser"
        password = "P@ssw0rd"
        user_type = StandardClient
        balance = 0.0

        users = {}
        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)

        # Check permissions that should be true for a StandardClient
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA))
        # Check permissions that should be false for a StandardClient
        self.assertFalse(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))

    def test_teller_business_hours(self):
        """
        Test the business hours check for a Teller.
        """
        username = "testteller"
        password = "P@ssw0rd"
        user_type = Teller

        users = {}
        insert_user(users, username, password, user_type)
        user_data = users[username]
        teller = Teller(username, user_data['hashed_password'])

        # Simulate within business hours
        with freeze_time("2024-11-15 12:00:00"):
            self.assertTrue(teller.is_within_business_hours())

        # Simulate outside business hours
        with freeze_time("2024-11-15 18:00:00"):
            self.assertFalse(teller.is_within_business_hours())

if __name__ == "__main__":
    unittest.main()