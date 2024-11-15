import unittest
from freezegun import freeze_time
import datetime
from main import PasswordManager, User, Role, Permissions, StandardClient, PremiumClient, Teller, FinancialAdvisor, FinancialPlanner
from main import insert_user, authenticate, load_users_from_file, save_users_to_file, password_LUDS

class TestPasswordManager(unittest.TestCase):

    def test_hash_password(self):
        password = "P@ssw0rd"
        hashed_password = PasswordManager.hash_password(password)
        self.assertIsInstance(hashed_password, bytes)
        self.assertGreater(len(hashed_password), len(password.encode()))

    def test_verify_password(self):
        password = "P@ssw0rd"
        hashed_password = PasswordManager.hash_password(password)
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))
        self.assertFalse(PasswordManager.verify_password("WrongPassword", hashed_password))

    def test_password_LUDS(self):
        # Test valid password
        password = "P@ssw0rd"
        self.assertTrue(password_LUDS(password, "testuser"))

        # Test password too short
        password = "P@ss"
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test password too long
        password = "P@ssw0rd" * 10
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test missing uppercase
        password = "p@ssw0rd"
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test missing lowercase
        password = "P@SSW0RD"
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test missing digit
        password = "P@ssword"
        self.assertFalse(password_LUDS(password, "testuser"))

        # Test missing special character
        password = "Passw0rd"
        self.assertFalse(password_LUDS(password, "testuser"))

    def test_insert_user(self):
        users = {}
        username = "testuser"
        password = "P@ssw0rd"
        user_type = StandardClient
        balance = 0.0

        self.assertTrue(insert_user(users, username, password, user_type, balance))
        self.assertIn(username, users)

    def test_authenticate_user(self):
        users = {}
        username = "testuser"
        password = "P@ssw0rd"
        user_type = StandardClient
        balance = 0.0

        insert_user(users, username, password, user_type, balance)
        self.assertTrue(authenticate(users, username, password))
        self.assertFalse(authenticate(users, username, "WrongPassword"))

    def test_load_and_save_users(self):
        users = {}
        username = "testuser"
        password = "P@ssw0rd"
        user_type = StandardClient
        balance = 0.0

        insert_user(users, username, password, user_type, balance)
        save_users_to_file(users, 'passwd.txt')
        loaded_users = load_users_from_file('passwd.txt')
        self.assertIn(username, loaded_users)

    def test_user_roles_and_permissions(self):
        username = "testuser"
        password = "P@ssw0rd"
        user_type = StandardClient
        balance = 0.0

        users = {}
        insert_user(users, username, password, user_type, balance)
        user_data = users[username]
        user = StandardClient(username, user_data['hashed_password'], balance)

        self.assertTrue(user.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(user.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(user.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA))
        self.assertFalse(user.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))

    def test_teller_business_hours(self):
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