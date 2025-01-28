def caesar_cipher(text, shift, mode='encrypt'):
    """
    Implements a Caesar cipher for encryption and decryption. This function can
    either encrypt or decrypt a given text depending on the 'mode' argument.
    
    The Caesar cipher shifts the letters of the alphabet by a specified number
    (shift value), and wraps around when reaching the end of the alphabet.

    Args:
    - text (str): The input text (message) to be encrypted or decrypted.
    - shift (int): The number of positions each letter should be shifted. Can be negative for decryption.
    - mode (str): The operation mode. Should be 'encrypt' for encryption and 'decrypt' for decryption.
    
    Returns:
    - str: The encrypted or decrypted text.
    
    Raises:
    - ValueError: If the mode is not 'encrypt' or 'decrypt'.
    - TypeError: If the text is not a string or shift is not an integer.
    """
    
    # Validate input types
    if not isinstance(text, str):
        raise TypeError("The 'text' parameter must be a string.")
    if not isinstance(shift, int):
        raise TypeError("The 'shift' parameter must be an integer.")
    if mode not in ['encrypt', 'decrypt']:
        raise ValueError("The 'mode' parameter must be either 'encrypt' or 'decrypt'.")
    
    # Handle encryption or decryption mode
    if mode == 'decrypt':
        # For decryption, shift value is negative of the provided shift
        shift = -shift

    # Initialize the result string
    result = ""

    # Iterate over each character in the text
    for char in text:
        # Check if the character is an alphabet letter
        if char.isalpha():
            # Determine the base (either uppercase or lowercase)
            shift_base = 65 if char.isupper() else 97

            # Perform the Caesar cipher shift and wrap around using modulo arithmetic
            shifted_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)

            # Append the shifted character to the result
            result += shifted_char
        else:
            # If the character is not alphabetic, simply add it to the result without modification
            result += char

    # Log the transformation for debugging purposes (can be turned off later)
    print(f"Original Text: {text}")
    print(f"Shift: {shift}")
    print(f"Mode: {mode}")
    print(f"Transformed Text: {result}")

    # Return the final result (either encrypted or decrypted text)
    return result


# Example of usage
if __name__ == "__main__":
    # Sample text to encrypt or decrypt
    sample_text = "Hello World! Let's test the Caesar Cipher."
    
    # Example 1: Encrypt the text with a shift of 3
    encrypted_text = caesar_cipher(sample_text, 3, mode='encrypt')
    print(f"Encrypted: {encrypted_text}")

    # Example 2: Decrypt the text with a shift of 3
    decrypted_text = caesar_cipher(encrypted_text, 3, mode='decrypt')
    print(f"Decrypted: {decrypted_text}")

    # Example 3: Encrypt with a negative shift for a different outcome
    encrypted_negative_shift = caesar_cipher(sample_text, -5, mode='encrypt')
    print(f"Encrypted with Negative Shift: {encrypted_negative_shift}")
