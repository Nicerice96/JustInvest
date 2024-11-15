import unittest
from main import * 

class TestJustInvestSystem(unittest.TestCase):

    def test_register_user(self):
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        self.assertTrue(insert_user(users, username, password, user_type, balance))
        self.assertIn(username, users)
        self.assertNotEqual(users[username]['hashed_password'], password)

    def test_login_user(self):
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        self.assertTrue(authenticate(users, username, password))

    def test_login_user_invalid_credentials(self):
        users = {}
        username = "test_user"
        password = "P@ssw0rd1"
        user_type = StandardClient
        balance = 1000.0

        insert_user(users, username, password, user_type, balance)
        self.assertFalse(authenticate(users, username, "wrong_password"))

    def test_standard_client_permissions(self):
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
        common_passwords = load_common_passwords("10k-most-common.txt")
        users = {}
        username = "test_user"
        password = "password123"  # Assuming this is a common password
        user_type = StandardClient
        balance = 1000.0

        self.assertFalse(insert_user(users, username, password, user_type, balance))

    def test_luds_password_validation(self):
        users = {}
        username = "test_user"
        password = "short"  # Password does not meet LUDS criteria
        user_type = StandardClient
        balance = 1000.0

        self.assertFalse(insert_user(users, username, password, user_type, balance))

    def test_password_hashing(self):
        password = "P@ssw0rd1"
        hashed_password = PasswordManager.hash_password(password)
        self.assertNotEqual(hashed_password, password)
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))

    def test_password_verification(self):
        password = "P@ssw0rd1"
        wrong_password = "WrongPassword"
        hashed_password = PasswordManager.hash_password(password)
        self.assertTrue(PasswordManager.verify_password(password, hashed_password))
        self.assertFalse(PasswordManager.verify_password(wrong_password, hashed_password))

if __name__ == "__main__":
    unittest.main()