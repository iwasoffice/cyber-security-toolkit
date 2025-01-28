import string
from utils import caesar_cipher, vigenere_cipher_encrypt, vigenere_cipher_decrypt

def encrypt_message(message, method, key):
    """
    Encrypt a message using the selected encryption method.

    Args:
        message (str): The plaintext message to encrypt.
        method (str): The encryption method ('caesar' or 'vigenere').
        key (Union[int, str]): The encryption key (integer for Caesar, string for Vigenère).

    Returns:
        str: The encrypted message.
    """
    if method == "caesar":
        if not isinstance(key, int):
            raise ValueError("Caesar cipher requires an integer key.")
        return caesar_cipher(message, key)
    elif method == "vigenere":
        if not isinstance(key, str):
            raise ValueError("Vigenère cipher requires a string key.")
        return vigenere_cipher_encrypt(message, key)
    else:
        raise ValueError("Unsupported encryption method. Choose 'caesar' or 'vigenere'.")

def decrypt_message(encrypted_message, method, key):
    """
    Decrypt a message using the selected encryption method.

    Args:
        encrypted_message (str): The encrypted message to decrypt.
        method (str): The encryption method ('caesar' or 'vigenere').
        key (Union[int, str]): The encryption key (integer for Caesar, string for Vigenère).

    Returns:
        str: The decrypted message.
    """
    if method == "caesar":
        if not isinstance(key, int):
            raise ValueError("Caesar cipher requires an integer key.")
        return caesar_cipher(encrypted_message, -key)
    elif method == "vigenere":
        if not isinstance(key, str):
            raise ValueError("Vigenère cipher requires a string key.")
        return vigenere_cipher_decrypt(encrypted_message, key)
    else:
        raise ValueError("Unsupported decryption method. Choose 'caesar' or 'vigenere'.")

def get_user_choice():
    """
    Display the menu and get the user's choice.

    Returns:
        tuple: (choice, method, key, message)
    """
    print("\nEncryption/Decryption Tool")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    
    choice = input("Choose an option (1 or 2): ").strip()
    if choice not in ["1", "2"]:
        raise ValueError("Invalid choice. Please select 1 or 2.")

    method = input("Choose encryption method (caesar or vigenere): ").strip().lower()
    if method not in ["caesar", "vigenere"]:
        raise ValueError("Invalid method. Please select 'caesar' or 'vigenere'.")

    if method == "caesar":
        key = input("Enter the shift value (integer): ").strip()
        if not key.isdigit():
            raise ValueError("Shift value must be an integer.")
        key = int(key)
    else:
        key = input("Enter the encryption key (string): ").strip()
        if not key.isalpha():
            raise ValueError("Encryption key for Vigenère must contain only letters.")

    message = input("Enter your message: ").strip()
    return choice, method, key, message

if __name__ == "__main__":
    try:
        choice, method, key, message = get_user_choice()

        if choice == "1":
            result = encrypt_message(message, method, key)
            print("\nEncrypted Message:", result)
        elif choice == "2":
            result = decrypt_message(message, method, key)
            print("\nDecrypted Message:", result)
    except ValueError as ve:
        print("Error:", ve)
    except Exception as e:
        print("An unexpected error occurred:", e)
