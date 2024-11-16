import unittest
from main import StandardClient, PremiumClient, Teller, FinancialAdvisor, FinancialPlanner, Permissions
from datetime import datetime
from freezegun import freeze_time

class TestUserPermissions(unittest.TestCase):
    """
    This class contains test cases for different user permissions.
    """

    def test_standard_client_permissions(self):
        """
        Test the permissions of a standard client.
        """
        standard_client_username = "standard_client"
        standard_client_password = b"password"
        standard_client_salt = b"salt"
        standard_client_balance = 1000.0
        standard_client = StandardClient(standard_client_username, standard_client_password, standard_client_salt, standard_client_balance)

        # Check permissions that should be true for a standard client
        self.assertTrue(standard_client.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(standard_client.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(standard_client.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA))
        
        # Check permissions that should be false for a standard client
        self.assertFalse(standard_client.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))
        self.assertFalse(standard_client.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP))
        self.assertFalse(standard_client.has_permission(Permissions.TELLER_ACCESS))

    def test_premium_client_permissions(self):
        """
        Test the permissions of a premium client.
        """
        premium_client_username = "premium_client"
        premium_client_password = b"password"
        premium_client_salt = b"salt"
        premium_client_balance = 2000.0
        premium_client = PremiumClient(premium_client_username, premium_client_password, premium_client_salt, premium_client_balance)

        # Check permissions that should be true for a premium client
        self.assertTrue(premium_client.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(premium_client.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(premium_client.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))
        self.assertTrue(premium_client.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP))
        
        # Check permissions that should be false for a premium client
        self.assertFalse(premium_client.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA))
        self.assertFalse(premium_client.has_permission(Permissions.TELLER_ACCESS))

    @freeze_time("2024-11-15 12:00:00")  # Freeze time to simulate business hours
    def test_teller_access_during_business_hours(self):
        """
        Test teller access during business hours.
        """
        teller_username = "teller"
        teller_password = b"password"
        teller_salt = b"salt"
        teller = Teller(teller_username, teller_password, teller_salt)

        self.assertTrue(teller.has_permission(Permissions.TELLER_ACCESS))

    @freeze_time("2024-11-15 18:00:00")  # Freeze time to simulate outside business hours
    def test_teller_access_outside_business_hours(self):
        """
        Test teller access outside business hours.
        """
        teller_username = "teller"
        teller_password = b"password"
        teller_salt = b"salt"
        teller = Teller(teller_username, teller_password, teller_salt)

        self.assertFalse(teller.has_permission(Permissions.TELLER_ACCESS))

    def test_financial_advisor_permissions(self):
        """
        Test the permissions of a financial advisor.
        """
        financial_advisor_username = "financial_advisor"
        financial_advisor_password = b"password"
        financial_advisor_salt = b"salt"
        financial_advisor = FinancialAdvisor(financial_advisor_username, financial_advisor_password, financial_advisor_salt)

        # Check permissions that should be true for a financial advisor
        self.assertTrue(financial_advisor.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(financial_advisor.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(financial_advisor.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))
        self.assertTrue(financial_advisor.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA))
        self.assertTrue(financial_advisor.has_permission(Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS))
        
        # Check permissions that should be false for a financial advisor
        self.assertFalse(financial_advisor.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP))
        self.assertFalse(financial_advisor.has_permission(Permissions.VIEW_MONEY_MARKET_INSTRUMENTS))

    def test_financial_planner_permissions(self):
        """
        Test the permissions of a financial planner.
        """
        financial_planner_username = "financial_planner"
        financial_planner_password = b"password"
        financial_planner_salt = b"salt"
        financial_planner = FinancialPlanner(financial_planner_username, financial_planner_password, financial_planner_salt)

        # Check permissions that should be true for a financial planner
        self.assertTrue(financial_planner.has_permission(Permissions.CLIENT_VIEW_BALANCE))
        self.assertTrue(financial_planner.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO))
        self.assertTrue(financial_planner.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO))
        self.assertTrue(financial_planner.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP))
        self.assertTrue(financial_planner.has_permission(Permissions.VIEW_MONEY_MARKET_INSTRUMENTS))
        self.assertTrue(financial_planner.has_permission(Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS))
        
        # Check permissions that should be false for a financial planner
        self.assertFalse(financial_planner.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA))

if __name__ == "__main__":
    unittest.main()