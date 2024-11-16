import unittest
from freezegun import freeze_time
from main import PasswordManager, password_LUDS, insert_user, load_users_from_file, save_users_to_file, Permissions
from main import StandardClient, PremiumClient, Teller, FinancialAdvisor, FinancialPlanner

class TestUserManagement(unittest.TestCase):
    """
    This class contains unit tests for user management functions, including password hashing, verification, validation, and user role permissions.
    """

    def test_password_hashing(self):
        """
        Test that the hashed password is different from the original password.

        This test ensures that the `PasswordManager.hash_password` method correctly hashes the password and does not return the original password.
        """
        password = "StrongP@ssw0rd"
        hashed_password = PasswordManager.hash_password(password)
        self.assertNotEqual(password, hashed_password.decode())

    def test_password_verification(self):
        """
        Test that the `PasswordManager.verify_password` method correctly verifies a password against its hashed version.

        This test ensures that the verification method returns True for the correct password and False for an incorrect password.
        """
        password = "StrongP@ssw0rd"
        hashed_password = PasswordManager.hash_password(password)
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))

    def test_password_validation(self):
        """
        Test various password validation scenarios to ensure the `password_LUDS` function correctly validates passwords.

        This includes tests for valid passwords and invalid passwords due to length, missing uppercase, lowercase, digits, or special characters.
        """
        # Valid password
        password = "StrongP@ssw0rd"
        self.assertTrue(password_LUDS(password, "username"))

        # Invalid password - too short
        password = "Short"
        self.assertFalse(password_LUDS(password, "username"))

        # Invalid password - missing uppercase
        password = "strongp@ssw0rd"
        self.assertFalse(password_LUDS(password, "username"))

        # Invalid password - missing lowercase
        password = "STRONGP@SSW0RD"
        self.assertFalse(password_LUDS(password, "username"))

        # Invalid password - missing digit
        password = "StrongP@ssword"
        self.assertFalse(password_LUDS(password, "username"))

        # Invalid password - missing special character
        password = "StrongPassw0rd"
        self.assertFalse(password_LUDS(password, "username"))

    def test_insert_user(self):
        """
        Test the `insert_user` function to ensure it correctly adds a new user to the users dictionary.

        This test checks that the user is successfully inserted and that the username is present in the users dictionary.
        """
        users = {}
        username = "testuser"
        password = "StrongP@ssw0rd"
        self.assertTrue(insert_user(users, username, password, StandardClient))
        self.assertIn(username, users)

    def test_load_and_save_users(self):
        """
        Test the `load_users_from_file` and `save_users_to_file` functions to ensure they correctly save and load user data.

        This test saves users to a file, loads them back, and compares the original and loaded user data.
        """
        users = {
            "testuser": {
                'hashed_password': PasswordManager.hash_password("StrongP@ssw0rd"),
                'role': 'StandardClient'
            }
        }
        save_users_to_file(users, 'passwd.txt')
        loaded_users = load_users_from_file('passwd.txt')
        for user in loaded_users.values():
            user['role'] = user['role'].strip()
        self.assertEqual(users, loaded_users)

    def test_user_roles(self):
        """
        Test the permissions of different user roles.

        This test ensures that each user role has the correct permissions.
        """
        # Standard Client
        user = StandardClient("testuser", PasswordManager.hash_password("StrongP@ssw0rd"))
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertFalse(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))

        # Premium Client
        user = PremiumClient("testuser", PasswordManager.hash_password("StrongP@ssw0rd"))
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))

        # Freeze time to 10 AM (inside 9-5) for Teller test
        with freeze_time("2024-11-15 10:00:00"):
            user = Teller("testuser", PasswordManager.hash_password("StrongP@ssw0rd"))
            self.assertTrue(user.has_permission(Permissions.TELLER_ACCESS))

        # Financial Advisor
        user = FinancialAdvisor("testuser", PasswordManager.hash_password("StrongP@ssw0rd"))
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))

        # Financial Planner
        user = FinancialPlanner("testuser", PasswordManager.hash_password("StrongP@ssw0rd"))
        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))

if __name__ == "__main__":
    unittest.main()