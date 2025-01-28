import re
import time
import string
import random

def check_password_strength(password):
    """
    Check the strength of a password based on multiple criteria:
    - Minimum length of 8 characters
    - Contains at least one lowercase letter
    - Contains at least one uppercase letter
    - Contains at least one digit
    - Contains at least one special character
    - Does not contain spaces

    Returns a message indicating password strength and improvement suggestions.
    """
    issues = []

    # Check for minimum length
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long.")

    # Check for lowercase letters
    if not re.search("[a-z]", password):
        issues.append("Password must include at least one lowercase letter.")

    # Check for uppercase letters
    if not re.search("[A-Z]", password):
        issues.append("Password must include at least one uppercase letter.")

    # Check for digits
    if not re.search("[0-9]", password):
        issues.append("Password must include at least one number.")

    # Check for special characters
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        issues.append("Password must include at least one special character.")

    # Check for spaces
    if " " in password:
        issues.append("Password must not contain spaces.")

    if issues:
        return f"Weak Password:\n- " + "\n- ".join(issues)
    else:
        return "Strong Password: Your password meets all the security requirements!"

def generate_strong_password(length=12):
    """
    Generate a strong random password containing:
    - Uppercase letters
    - Lowercase letters
    - Digits
    - Special characters

    Parameters:
    length (int): The length of the generated password (default is 12).

    Returns:
    str: A randomly generated strong password.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    all_characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    password = ''.join(random.choice(all_characters) for _ in range(length))

    # Ensure the generated password meets all criteria
    while (not re.search("[a-z]", password) or
           not re.search("[A-Z]", password) or
           not re.search("[0-9]", password) or
           not re.search("[!@#$%^&*(),.?\":{}|<>]", password) or
           " " in password):
        password = ''.join(random.choice(all_characters) for _ in range(length))

    return password

def password_strength_menu():
    """
    Display a menu to the user for password checking and generation.
    """
    print("Welcome to the Password Strength Checker and Generator!\n")
    while True:
        print("Please select an option:")
        print("1. Check password strength")
        print("2. Generate a strong password")
        print("3. Exit")

        try:
            choice = int(input("\nEnter your choice (1/2/3): "))
        except ValueError:
            print("Invalid input. Please enter 1, 2, or 3.\n")
            continue

        if choice == 1:
            user_password = input("\nEnter a password to check its strength: ")
            print("\nAnalyzing password...")
            time.sleep(1)  # Simulate analysis time
            result = check_password_strength(user_password)
            print(f"\n{result}\n")
        elif choice == 2:
            try:
                length = int(input("\nEnter the desired length for the password (minimum 8): "))
                if length < 8:
                    print("Password length must be at least 8 characters.\n")
                    continue
                strong_password = generate_strong_password(length)
                print(f"\nGenerated Strong Password: {strong_password}\n")
            except ValueError:
                print("Invalid input. Please enter a number.\n")
        elif choice == 3:
            print("\nThank you for using the Password Strength Checker and Generator! Goodbye!\n")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.\n")

if __name__ == "__main__":
    password_strength_menu()
