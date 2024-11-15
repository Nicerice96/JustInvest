from enum import Enum
from datetime import datetime
from freezegun import freeze_time

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
    def __init__(self, role_type: str, permissions: list[Permissions]):
        self.role_type = role_type
        self.permissions = permissions

# Base class for users
class User:
    """Base class for users with common attributes and methods."""
    def __init__(self, username: str, hashed_password: bytes, salt: bytes, role: Role):
        self.username = username
        self.hashed_password = hashed_password
        self.salt = salt
        self.role = role

    def has_permission(self, permission: Permissions) -> bool:
        """Check if the user has a specific permission."""
        return permission in self.role.permissions

# Class for Standard Client users
class StandardClient(User):
    def __init__(self, username: str, hashed_password: bytes, salt: bytes, balance: float = 0.0):
        super().__init__(
            username,
            hashed_password,
            salt,
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
    def __init__(self, username: str, hashed_password: bytes, salt: bytes, balance: float = 0.0):
        super().__init__(
            username,
            hashed_password,
            salt,
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
    def __init__(self, username: str, hashed_password: bytes, salt: bytes):
        super().__init__(
            username,
            hashed_password,
            salt,
            Role(
                "Teller",
                [Permissions.TELLER_ACCESS]
            )
        )

    def has_permission(self, permission: Permissions) -> bool:
        """Check if the Teller has a specific permission, considering business hours."""
        if permission == Permissions.TELLER_ACCESS:
            if not self.is_within_business_hours():
                print("Access denied. Teller access is only allowed during business hours (9:00am to 5:00pm).")
                return False
        return super().has_permission(permission)

    def is_within_business_hours(self) -> bool:
        """Check if the current time is within business hours (9:00 AM to 5:00 PM)."""
        current_time = datetime.now().time()
        start_time = datetime.strptime("09:00", "%H:%M").time()
        end_time = datetime.strptime("17:00", "%H:%M").time()
        return start_time <= current_time <= end_time

# Class for Financial Advisor users
class FinancialAdvisor(User):
    """Class for Financial Advisor users."""
    def __init__(self, username: str, hashed_password: bytes, salt: bytes):
        super().__init__(
            username,
            hashed_password,
            salt,
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
    def __init__(self, username: str, hashed_password: bytes, salt: bytes):
        super().__init__(
            username,
            hashed_password,
            salt,
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

def main():
    # Create different types of users
    
    # TEST 1: Standard Client
    standard_client_username = "standard_client"
    standard_client_password = b"password"  # Example password, should be hashed in real use
    standard_client_salt = b"salt"  # Example salt, should be generated in real use
    standard_client_balance = 1000.0
    standard_client = StandardClient(standard_client_username, standard_client_password, standard_client_salt, standard_client_balance)
    
    assert standard_client.has_permission(Permissions.CLIENT_VIEW_BALANCE)
    assert standard_client.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO)
    assert standard_client.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA)
    assert not standard_client.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO)
    assert not standard_client.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP)
    
    # TEST 2: Premium Client
    premium_client_username = "premium_client"
    premium_client_password = b"password"  # Example password, should be hashed in real use
    premium_client_salt = b"salt"  # Example salt, should be generated in real use
    premium_client_balance = 2000.0
    premium_client = PremiumClient(premium_client_username, premium_client_password, premium_client_salt, premium_client_balance)
    
    assert premium_client.has_permission(Permissions.CLIENT_VIEW_BALANCE)
    assert premium_client.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO)
    assert premium_client.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO)
    assert premium_client.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP)
    assert not premium_client.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA)
    assert not premium_client.has_permission(Permissions.VIEW_MONEY_MARKET_INSTRUMENTS)
    
    # TEST 3: Teller
    teller_username = "teller"
    teller_password = b"password"
    teller_salt = b"salt"
    teller = Teller(teller_username, teller_password, teller_salt)

    @freeze_time("2024-11-15 12:00:00")
    def test_teller_access_during_business_hours():
        assert teller.has_permission(Permissions.TELLER_ACCESS)

    @freeze_time("2024-11-15 18:00:00")
    def test_teller_access_outside_business_hours():
        assert not teller.has_permission(Permissions.TELLER_ACCESS)
    
    # Run the tests for Teller access
    test_teller_access_during_business_hours()
    test_teller_access_outside_business_hours()
    
    # TEST 4: Financial Advisor
    financial_advisor_username = "financial_advisor"
    financial_advisor_password = b"password"  # Example password, should be hashed in real use
    financial_advisor_salt = b"salt"  # Example salt, should be generated in real use
    financial_advisor = FinancialAdvisor(financial_advisor_username, financial_advisor_password, financial_advisor_salt)
    assert financial_advisor.has_permission(Permissions.CLIENT_VIEW_BALANCE)
    assert financial_advisor.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO)
    assert financial_advisor.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO)
    assert financial_advisor.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA)
    assert financial_advisor.has_permission(Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS)
    assert not financial_advisor.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP)
    assert not financial_advisor.has_permission(Permissions.VIEW_MONEY_MARKET_INSTRUMENTS)
    
    # TEST 5: Financial Planner
    financial_planner_username = "financial_planner"
    financial_planner_password = b"password"  # Example password, should be hashed in real use
    financial_planner_salt = b"salt"  # Example salt, should be generated in real use
    financial_planner = FinancialPlanner(financial_planner_username, financial_planner_password, financial_planner_salt)
    assert financial_planner.has_permission(Permissions.CLIENT_VIEW_BALANCE)
    assert financial_planner.has_permission(Permissions.VIEW_CLIENT_PORTFOLIO)
    assert financial_planner.has_permission(Permissions.MODIFY_CLIENT_PORTFOLIO)
    assert financial_planner.has_permission(Permissions.VIEW_CONTACT_DETAILS_FP)
    assert financial_planner.has_permission(Permissions.VIEW_MONEY_MARKET_INSTRUMENTS)
    assert financial_planner.has_permission(Permissions.VIEW_PRIVATE_CONSUMER_INSTRUMENTS)
    assert not financial_planner.has_permission(Permissions.VIEW_CONTACT_DETAILS_FA)

    # Function to print permissions for each user
    def print_permissions(user: User):
        print(f"Permissions for {user.username} with role {user.role.role_type}:")
        for permission in Permissions:
            if user.has_permission(permission):
                print(f"- {permission.name}")
            else:
                print(f"- {permission.name} (Denied)")
        print()

    # Print permissions for each user
    print_permissions(standard_client)
    print_permissions(premium_client)
    print_permissions(teller)
    print_permissions(financial_advisor)
    print_permissions(financial_planner)

if __name__ == "__main__":
    main()