# Cybersecurity Toolkit

## Overview
The **Cybersecurity Toolkit** is a comprehensive suite of essential tools designed to aid in securing digital assets and enhancing online safety. It includes utilities for evaluating password strength, encrypting and decrypting sensitive data, and simulating basic firewall functionalities for IP address filtering. Whether you're a beginner or a seasoned cybersecurity enthusiast, this toolkit provides fundamental features that support security best practices.

### Key Features:
1. **Password Strength Checker** – Helps assess the strength of passwords by evaluating their length, diversity of character sets (lowercase, uppercase, numbers, and symbols), and adherence to common password standards.
2. **Encryption and Decryption Tool** – Uses the Caesar cipher to protect sensitive messages by shifting characters in the text, making it harder for unauthorized individuals to interpret the data without the correct shift value.
3. **Firewall Simulator** – Simulates basic firewall rules to test IP addresses against a predefined list of blocked addresses, providing a way to ensure only authorized users can access the network.

By incorporating these tools, the Cybersecurity Toolkit aims to simplify key aspects of security, making it easier to understand and implement in both personal and professional environments.

---

## Features
- **Password Strength Analysis:** Ensures passwords meet common security requirements and provides feedback on how to improve them.
- **Message Encryption and Decryption:** Encrypts and decrypts messages with a simple Caesar cipher, allowing users to secure communication or data.
- **Firewall Simulation for IP Blocking:** Simulates firewall behavior to check if an IP address is blocked based on a predefined list, helping test network security settings.

---

## Usage

### 1. Password Strength Checker (`password_checker.py`)
The password strength checker evaluates the complexity of a password and ensures that it meets recommended security standards. It checks for a combination of:
- Minimum length of 8 characters
- Presence of lowercase and uppercase letters
- Inclusion of numbers
- Usage of special characters

- To run the password checker, execute the following command:

  ```bash
  python password_checker.py
You'll be prompted to enter a password. The program will evaluate the password and provide feedback on its strength.

### 2. Encrypt/Decrypt Messages (encrypt_decrypt.py)
This tool uses a Caesar cipher to encrypt and decrypt messages. You can encrypt sensitive information with a shift value (for encryption), and later decrypt it by applying the inverse shift (for decryption).

- To use the encryption or decryption tool, run the following command:

  ```bash
  python encrypt_decrypt.py
You will be asked to:
- Choose whether to encrypt or decrypt a message.
- Enter the message you want to encrypt or decrypt.
- Provide a shift value (e.g., 3 for encryption or -3 for decryption).
- The program will display the result of the encryption or decryption process.

### 3. Firewall Simulator (firewall_simulator.py)
The firewall simulator allows you to test basic firewall functionality by checking whether an IP address is allowed to access the network. It compares a given IP address with a predefined list of blocked IP addresses.

- To run the firewall simulator, use the following command:

  ```bash
  python firewall_simulator.py
You will be prompted to enter an IP address, and the tool will tell you whether that IP is allowed or blocked based on the firewall rules.

---

## File Structure

The project consists of the following files:

- **`password_checker.py`**: A script that checks the strength of passwords, ensuring they follow good security practices.
- **`encrypt_decrypt.py`**: A script that handles message encryption and decryption using the Caesar cipher.
- **`firewall_simulator.py`**: A script to simulate firewall operations by checking if an IP is allowed or blocked.
- **`utils.py`**: Contains shared functions like the Caesar cipher implementation used by other scripts.
- **`README.md`**: The documentation for the Cybersecurity Toolkit, explaining how to use the tools and providing an overview of the project.

---

## Requirements

This toolkit is built with Python 3.x, and requires no external dependencies, as it relies solely on Python's built-in libraries. You can run the scripts directly on any system with Python 3.x installed.

---

## Author

**Olawale Iwarere**

Feel free to contribute to the toolkit, raise issues, or suggest improvements. This project aims to help individuals learn and implement basic cybersecurity practices with minimal effort.

---

## Contribution

Feel free to fork this repository and submit pull requests to improve or add new features. Contributions are always welcome!

---

## License

This project is licensed under the MIT License. See the LICENSE file for more information.
