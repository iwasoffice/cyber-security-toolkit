import re
import datetime

class FirewallSimulator:
    """
    A class to simulate a basic firewall with IP validation, blocking rules, logging, and dynamic updates.
    """

    def __init__(self):
        self.blocked_ips = ["192.168.1.1", "10.0.0.2", "172.16.0.3"]
        self.blocked_subnets = []  # Store blocked subnets in CIDR format
        self.log_file = "firewall_logs.txt"

    def validate_ip(self, ip_address):
        """
        Validates an IP address format.
        """
        pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        match = re.match(pattern, ip_address)
        if match:
            # Ensure each octet is between 0 and 255
            return all(0 <= int(octet) <= 255 for octet in match.groups())
        return False

    def is_ip_blocked(self, ip_address):
        """
        Checks if an IP address is blocked directly or by subnet.
        """
        if ip_address in self.blocked_ips:
            return True

        for subnet in self.blocked_subnets:
            if self.is_ip_in_subnet(ip_address, subnet):
                return True

        return False

    def is_ip_in_subnet(self, ip_address, subnet):
        """
        Checks if an IP address belongs to a given subnet.
        """
        try:
            from ipaddress import ip_address as ip_obj, ip_network
            return ip_obj(ip_address) in ip_network(subnet, strict=False)
        except ValueError:
            return False

    def log_access_attempt(self, ip_address, status):
        """
        Logs access attempts with a timestamp.
        """
        with open(self.log_file, "a") as log:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"{timestamp} - {ip_address} - {status}\n")

    def add_blocked_ip(self, ip_address):
        """
        Dynamically adds an IP address to the blocked list.
        """
        if self.validate_ip(ip_address):
            self.blocked_ips.append(ip_address)
            print(f"IP address {ip_address} has been added to the blocked list.")
        else:
            print("Invalid IP address format. Cannot block.")

    def add_blocked_subnet(self, subnet):
        """
        Dynamically adds a subnet to the blocked list.
        """
        try:
            from ipaddress import ip_network
            ip_network(subnet, strict=False)  # Validate subnet format
            self.blocked_subnets.append(subnet)
            print(f"Subnet {subnet} has been added to the blocked list.")
        except ValueError:
            print("Invalid subnet format. Cannot block.")

    def simulate_firewall(self, ip_address):
        """
        Simulates the firewall by checking if an IP address is blocked.
        """
        if not self.validate_ip(ip_address):
            return "Error: Invalid IP address format."

        if self.is_ip_blocked(ip_address):
            self.log_access_attempt(ip_address, "Blocked")
            return f"Blocked: {ip_address} is not allowed."

        self.log_access_attempt(ip_address, "Allowed")
        return f"Allowed: {ip_address} can access the network."

if __name__ == "__main__":
    firewall = FirewallSimulator()

    while True:
        print("\nFirewall Simulator Menu:")
        print("1. Check IP Address Access")
        print("2. Add Blocked IP")
        print("3. Add Blocked Subnet")
        print("4. View Blocked IPs")
        print("5. View Blocked Subnets")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            ip = input("Enter the IP address to check: ")
            result = firewall.simulate_firewall(ip)
            print(result)

        elif choice == "2":
            ip_to_block = input("Enter the IP address to block: ")
            firewall.add_blocked_ip(ip_to_block)

        elif choice == "3":
            subnet_to_block = input("Enter the subnet to block (e.g., 192.168.1.0/24): ")
            firewall.add_blocked_subnet(subnet_to_block)

        elif choice == "4":
            print("Blocked IPs:")
            for ip in firewall.blocked_ips:
                print(ip)

        elif choice == "5":
            print("Blocked Subnets:")
            for subnet in firewall.blocked_subnets:
                print(subnet)

        elif choice == "6":
            print("Exiting Firewall Simulator. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")
