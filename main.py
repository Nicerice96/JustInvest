from enum import Enum
from datetime import datetime

class Permissions(Enum):
    CLIENT_VIEW_BALANCE = 1
    VIEW_CLIENT_PORTFOLIO = 2
    VIEW_CONTACT_DETAILS_FA = 3
    MODIFY_CLIENT_PORTFOLIO = 4
    VIEW_CONTACT_DETAILS_FP = 5
    VIEW_MONEY_MARKET_INSTRUMENTS = 6
    VIEW_PRIVATE_CONSUMER_INSTRUMENTS = 7
    TELLER_ACCESS = 8

class Role:
    def __init__(self, role_type: str, permissions: list[Permissions]):
        self.role_type = role_type
        self.permissions = permissions

class User:
    def __init__(self, username: str, hashed_password: bytes, salt: bytes, role: Role):
        self.username = username
        self.hashed_password = hashed_password
        self.salt = salt
        self.role = role

    def has_permission(self, permission: Permissions) -> bool:
        return permission in self.role.permissions

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

class Teller(User):
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
        if permission == Permissions.TELLER_ACCESS:
            if not self.is_within_business_hours():
                print("Access denied. Teller access is only allowed during business hours (9:00am to 5:00pm).")
                return False
        return super().has_permission(permission)

    def is_within_business_hours(self) -> bool:
        current_time = datetime.now().time()
        start_time = datetime.strptime("09:00", "%H:%M").time()
        end_time = datetime.strptime("17:00", "%H:%M").time()
        return start_time <= current_time <= end_time

class FinancialAdvisor(User):
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

class FinancialPlanner(User):
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
    standard_client_username = "standard_client"
    standard_client_password = b"password"  # Example password, should be hashed in real use
    standard_client_salt = b"salt"  # Example salt, should be generated in real use
    standard_client_balance = 1000.0
    standard_client = StandardClient(standard_client_username, standard_client_password, standard_client_salt, standard_client_balance)

    premium_client_username = "premium_client"
    premium_client_password = b"password"  # Example password, should be hashed in real use
    premium_client_salt = b"salt"  # Example salt, should be generated in real use
    premium_client_balance = 2000.0
    premium_client = PremiumClient(premium_client_username, premium_client_password, premium_client_salt, premium_client_balance)

    teller_username = "teller"
    teller_password = b"password"  # Example password, should be hashed in real use
    teller_salt = b"salt"  # Example salt, should be generated in real use
    teller = Teller(teller_username, teller_password, teller_salt)

    financial_advisor_username = "financial_advisor"
    financial_advisor_password = b"password"  # Example password, should be hashed in real use
    financial_advisor_salt = b"salt"  # Example salt, should be generated in real use
    financial_advisor = FinancialAdvisor(financial_advisor_username, financial_advisor_password, financial_advisor_salt)

    financial_planner_username = "financial_planner"
    financial_planner_password = b"password"  # Example password, should be hashed in real use
    financial_planner_salt = b"salt"  # Example salt, should be generated in real use
    financial_planner = FinancialPlanner(financial_planner_username, financial_planner_password, financial_planner_salt)

    # Print permissions for each user
    def print_permissions(user: User):
        print(f"Permissions for {user.username} with role {user.role.role_type}:")
        for permission in Permissions:
            if user.has_permission(permission):
                print(f"- {permission.name}")
            else:
                print(f"- {permission.name} (Denied)")
        print()

    print_permissions(standard_client)
    print_permissions(premium_client)
    print_permissions(teller)
    print_permissions(financial_advisor)
    print_permissions(financial_planner)

if __name__ == "__main__":
    main()