import os
import subprocess

# Function to check the current firewall status
def check_firewall_status():
    """
    This function checks the current status of the firewall on the system.
    It uses system commands to determine whether the firewall is active or inactive.
    
    Returns:
    - str: A message indicating whether the firewall is running or not.
    """
    try:
        # Run the 'ufw' command to check if the firewall is active
        status = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
        
        # Check if the firewall is active based on the status output
        if "active" in status.stdout.lower():
            return "Firewall is currently ACTIVE."
        else:
            return "Firewall is currently INACTIVE."
    except FileNotFoundError:
        return "Error: 'ufw' command not found. Ensure UFW (Uncomplicated Firewall) is installed."
    except Exception as e:
        return f"An error occurred while checking firewall status: {e}"

# Function to enable the firewall
def enable_firewall():
    """
    This function enables the firewall on the system using the 'ufw' command.
    It runs the necessary commands to enable the firewall and ensure it starts at boot.

    Returns:
    - str: A message indicating whether the firewall was successfully enabled.
    """
    try:
        # Run the command to enable the firewall
        subprocess.run(['sudo', 'ufw', 'enable'], check=True)
        return "Firewall has been successfully enabled."
    except subprocess.CalledProcessError:
        return "Error: Unable to enable the firewall."
    except Exception as e:
        return f"An error occurred while enabling the firewall: {e}"

# Function to disable the firewall
def disable_firewall():
    """
    This function disables the firewall on the system using the 'ufw' command.
    It runs the necessary commands to disable the firewall.

    Returns:
    - str: A message indicating whether the firewall was successfully disabled.
    """
    try:
        # Run the command to disable the firewall
        subprocess.run(['sudo', 'ufw', 'disable'], check=True)
        return "Firewall has been successfully disabled."
    except subprocess.CalledProcessError:
        return "Error: Unable to disable the firewall."
    except Exception as e:
        return f"An error occurred while disabling the firewall: {e}"

# Function to add a firewall rule to allow an IP address
def allow_ip(ip_address):
    """
    This function adds a firewall rule to allow an IP address to access the system.
    The rule is added using the 'ufw' command to ensure that the IP can communicate with the system.

    Args:
    - ip_address (str): The IP address to allow.

    Returns:
    - str: A message indicating whether the IP was successfully allowed.
    """
    try:
        # Run the command to allow the IP address through the firewall
        subprocess.run(['sudo', 'ufw', 'allow', from_str(ip_address)], check=True)
        return f"IP address {ip_address} has been allowed through the firewall."
    except subprocess.CalledProcessError:
        return f"Error: Unable to allow IP address {ip_address} through the firewall."
    except Exception as e:
        return f"An error occurred while allowing IP address {ip_address}: {e}"

# Function to add a firewall rule to block an IP address
def block_ip(ip_address):
    """
    This function adds a firewall rule to block an IP address from accessing the system.
    The rule is added using the 'ufw' command to ensure that the IP is denied access.

    Args:
    - ip_address (str): The IP address to block.

    Returns:
    - str: A message indicating whether the IP was successfully blocked.
    """
    try:
        # Run the command to block the IP address through the firewall
        subprocess.run(['sudo', 'ufw', 'deny', from_str(ip_address)], check=True)
        return f"IP address {ip_address} has been blocked from accessing the system."
    except subprocess.CalledProcessError:
        return f"Error: Unable to block IP address {ip_address} through the firewall."
    except Exception as e:
        return f"An error occurred while blocking IP address {ip_address}: {e}"

# Function to delete a firewall rule allowing an IP address
def delete_allowed_ip(ip_address):
    """
    This function deletes a rule allowing an IP address from the firewall.
    It runs the 'ufw' command to remove the specific allow rule.

    Args:
    - ip_address (str): The IP address whose allow rule should be deleted.

    Returns:
    - str: A message indicating whether the rule was successfully deleted.
    """
    try:
        # Run the command to delete the allow rule for the given IP address
        subprocess.run(['sudo', 'ufw', 'delete', 'allow', from_str(ip_address)], check=True)
        return f"Allow rule for IP address {ip_address} has been removed."
    except subprocess.CalledProcessError:
        return f"Error: Unable to remove allow rule for IP address {ip_address}."
    except Exception as e:
        return f"An error occurred while removing the allow rule for IP address {ip_address}: {e}"

# Function to delete a firewall rule blocking an IP address
def delete_blocked_ip(ip_address):
    """
    This function deletes a rule blocking an IP address from the firewall.
    It runs the 'ufw' command to remove the specific deny rule.

    Args:
    - ip_address (str): The IP address whose block rule should be deleted.

    Returns:
    - str: A message indicating whether the rule was successfully deleted.
    """
    try:
        # Run the command to delete the block rule for the given IP address
        subprocess.run(['sudo', 'ufw', 'delete', 'deny', from_str(ip_address)], check=True)
        return f"Block rule for IP address {ip_address} has been removed."
    except subprocess.CalledProcessError:
        return f"Error: Unable to remove block rule for IP address {ip_address}."
    except Exception as e:
        return f"An error occurred while removing the block rule for IP address {ip_address}: {e}"

# Utility function to handle IP address formatting for `ufw` command
def from_str(ip_address):
    """
    This function formats the given IP address as a valid argument for the 'ufw' command.
    It adds the 'from' keyword before the IP address to match the 'ufw' syntax.

    Args:
    - ip_address (str): The IP address to format.

    Returns:
    - str: The formatted string to be used in 'ufw' commands.
    """
    return f"from {ip_address}"

# Function to view the current firewall rules
def view_firewall_rules():
    """
    This function retrieves and displays the current firewall rules.
    It runs the 'ufw status' command to show allowed and blocked IPs and services.

    Returns:
    - str: The current status and rules of the firewall.
    """
    try:
        # Run the 'ufw status' command to view the current firewall rules
        rules = subprocess.run(['sudo', 'ufw', 'status', 'verbose'], capture_output=True, text=True)
        return rules.stdout
    except subprocess.CalledProcessError:
        return "Error: Unable to retrieve firewall rules."
    except Exception as e:
        return f"An error occurred while retrieving firewall rules: {e}"

# Function to reset the firewall rules
def reset_firewall():
    """
    This function resets the firewall rules to their default state.
    It runs the 'ufw reset' command to clear all user-added rules and configurations.

    Returns:
    - str: A message indicating whether the firewall has been reset.
    """
    try:
        # Run the command to reset the firewall to its default state
        subprocess.run(['sudo', 'ufw', 'reset'], check=True)
        return "Firewall has been successfully reset to default settings."
    except subprocess.CalledProcessError:
        return "Error: Unable to reset the firewall."
    except Exception as e:
        return f"An error occurred while resetting the firewall: {e}"

# Main function to manage firewall rules interactively
def main():
    """
    This function manages the firewall interactively, offering the user options
    to enable/disable the firewall, add/remove IP rules, and view the firewall status.

    Returns:
    - None: It prints the result of each action to the console.
    """
    while True:
        print("\nFirewall Configurator")
        print("1. Check Firewall Status")
        print("2. Enable Firewall")
        print("3. Disable Firewall")
        print("4. Allow an IP Address")
        print("5. Block an IP Address")
        print("6. Delete Allowed IP Address")
        print("7. Delete Blocked IP Address")
        print("8. View Current Firewall Rules")
        print("9. Reset Firewall")
        print("10. Exit")

        choice = input("Choose an option (1-10): ")

        if choice == '1':
            print(check_firewall_status())
        elif choice == '2':
            print(enable_firewall())
        elif choice == '3':
            print(disable_firewall())
        elif choice == '4':
            ip = input("Enter the IP address to allow: ")
            print(allow_ip(ip))
        elif choice == '5':
            ip = input("Enter the IP address to block: ")
            print(block_ip(ip))
        elif choice == '6':
            ip = input("Enter the IP address to remove from allowed list: ")
            print(delete_allowed_ip(ip))
        elif choice == '7':
            ip = input("Enter the IP address to remove from blocked list: ")
            print(delete_blocked_ip(ip))
        elif choice == '8':
            print(view_firewall_rules())
        elif choice == '9':
            print(reset_firewall())
        elif choice == '10':
            print("Exiting Firewall Configurator.")
            break
        else:
            print("Invalid choice. Please try again.")

# Run the main function to start the configurator
if __name__ == "__main__":
    main()
