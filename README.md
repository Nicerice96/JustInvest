## Overview❗
The justInvest System is a comprehensive application designed to manage user accounts, permissions, and financial operations. This system utilizes the `bcrypt` library for secure password hashing and verification, ensuring the protection of user credentials.

## Key Features 

<<<<<<< HEAD
### User Roles and Permissions 📋 
- The system supports multiple user roles, including `StandardClient`, `PremiumClient`, `Teller`, `FinancialAdvisor`, and `FinancialPlanner`.
- Each role is associated with specific permissions, such as viewing account balances, portfolios, and contact details, as well as modifying portfolios and accessing various financial instruments.

### Password Management and Security 🔒
- Passwords are _hashed_ using the `bcrypt` library, which provides strong security through _salted hashing_ and adjustable computation cost.
- In addition to salting, the system uses a secret value known as a _pepper_ that is combined with the password before hashing. This pepper is kept separate from the stored hashes, adding an extra layer of security against database breaches[4].
- Passwords must adhere to the LUDS format (Length, Uppercase, Digit, Special character) and must not be among the 10,000 most common passwords.

### User Authentication ✅
- Users can register and log in to the system, with authentication handled by comparing the provided password against the stored hashed password using `bcrypt.checkpw`.

### Financial Operations 📈📊
- Users can perform various financial operations based on their permissions, such as viewing and modifying their portfolios, checking balances, and accessing financial advisor or planner contact details.

## Installation and Setup ⚠️

### Dependencies
- `bcrypt` library for password hashing
- `enum` and `typing` for type definitions
- `datetime` for time-related operations

### Installation 🔨
To install the necessary dependencies, run the following command in your terminal (this was not necessary on the VM for some reason):
```bash
pip install bcrypt
=======
# How to Run

you may run the application via on the VM via: 

## TERMINAL:

>>>>>>> c576f54 (updated README.md)
```

### Running the Application 🏃
To run the justInvest System, execute the `main.py` file (after navigating to the project directory):

_On the VM for this assigment:_
```bash
python3 main.py
```

<<<<<<< HEAD
=======
# Note!
You have to register as a user (it will prompt you as to which type of user you want to be) in order to be able to login, you will see a text file appear in the project directory, that is where the inforamtion is stored. Some of the information is public, some of it is private (using salt and pepper as well as hashing schemes) : The security measures are discussed in the project write up.
>>>>>>> c576f54 (updated README.md)

## Usage

### Registering a User 🔑
1. Select the "Register" option from the main menu.
2. Enter a username, password, user type, and balance (if applicable).
3. The system will validate the password and create the user account if all criteria are met.

### Logging In 🔓
1. Select the "Login" option from the main menu.
2. Enter your username and password.
3. The system will authenticate your credentials and provide access to the UI based on your role.

### Using the UI 📱
- Once logged in, users can perform actions based on their permissions, such as viewing balances, portfolios, and contact details, or modifying their portfolios.
- Financial advisors and planners can select clients to interact with and perform actions on their behalf.

## Code Structure 🔧

### Classes
- `Permissions`: An enumeration of available permissions.
- `Role`: A class to hold a user's role and associated permissions.
- `PasswordManager`: A class for hashing and verifying passwords using `bcrypt`.
- `User`: A base class for users with common attributes and methods.
- `StandardClient`, `PremiumClient`, `Teller`, `FinancialAdvisor`, `FinancialPlanner`: Derived classes for different user roles.

### Functions
- `load_common_passwords`: Loads a set of common passwords from a file.
- `load_users_from_file`: Loads user data from a file.
- `save_users_to_file`: Saves user data to a file.
- `insert_user`: Inserts a new user into the system.
- `authenticate`: Authenticates a user's credentials.
- `password_LUDS`: Validates a password against the LUDS format and common passwords.
- `display_clients`: Displays a list of clients and allows selection.
- `just_invest_ui`: The main UI for interacting with the justInvest System.
- `create_sample_clients`: Creates sample client accounts.

## Security Considerations 🔐

### Password Hashing
- Passwords are hashed using `bcrypt`, which includes a salt to prevent rainbow table attacks.
- The computation cost of hashing can be adjusted to slow down the process, making brute-force attacks more difficult.
- **Peppering**: The system uses a pepper, a secret value that is combined with the password before hashing. This pepper is not stored in the database, providing an additional layer of security. Even if the database is compromised, the attacker will not have access to the pepper, making it harder to crack the passwords[4].

### Permission System
- Users can only perform actions that are within their assigned permissions, ensuring that sensitive operations are restricted.

## License
The justInvest System is released under the [MIT License](https://opensource.org/licenses/MIT).

## Acknowledgments
- The `bcrypt` library is used for password hashing and verification.
- The system uses a common password list found here: [10k-most-common github](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt)
- The system's design and implementation are based on best practices for secure password management and role-based access control.