import socket
import threading
from ipaddress import ip_network
import time

# Function to check if a specific port is open on an IP address
def scan_port(ip, port):
    """
    This function attempts to connect to a given IP address and port.
    It checks if the port is open or closed by trying to establish a connection.
    
    Args:
    - ip (str): The IP address to scan.
    - port (int): The port number to check for open/close status.

    Returns:
    - str: Returns a string indicating whether the port is open or closed.
    """
    # Create a new socket object using IPv4 and TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set a timeout to 1 second for connection attempts

    # Try to connect to the given IP and port
    try:
        result = sock.connect_ex((ip, port))  # connect_ex returns 0 if successful
        if result == 0:
            return f"Port {port} is OPEN on {ip}"
        else:
            return f"Port {port} is CLOSED on {ip}"
    except socket.error as err:
        # If an error occurs (e.g., connection timeout), return a closed status
        return f"Error connecting to {ip} on port {port}: {err}"
    finally:
        sock.close()  # Always close the socket after checking

# Function to scan multiple ports on a given IP
def scan_ports(ip, ports):
    """
    This function scans a list of ports on a single IP address.
    It checks each port to determine if it's open or closed.
    
    Args:
    - ip (str): The IP address to scan.
    - ports (list): A list of port numbers to check on the given IP.

    Returns:
    - None: It prints the status of each port.
    """
    print(f"Scanning ports on {ip}...")
    for port in ports:
        print(scan_port(ip, port))

# Function to scan a range of IP addresses
def scan_ip_range(ip_range, ports):
    """
    This function scans a range of IP addresses in a subnet to check which ones are active
    and which ports are open on each active host.

    Args:
    - ip_range (str): A subnet or IP address range to scan (e.g., '192.168.1.0/24').
    - ports (list): A list of port numbers to check for each active host in the IP range.

    Returns:
    - None: It prints the results for each active host and open ports.
    """
    print(f"Scanning IP range {ip_range}...")
    network = ip_network(ip_range)  # Create an IP network object
    active_ips = []  # List to store IPs of active hosts

    # Iterate through all IPs in the range and check for active hosts
    for ip in network.hosts():
        ip_str = str(ip)
        response = ping_host(ip_str)  # Ping the host to check if it's active
        if response:
            print(f"Host {ip_str} is ACTIVE.")
            active_ips.append(ip_str)
        else:
            print(f"Host {ip_str} is INACTIVE.")

    # Scan open ports on active hosts
    if active_ips:
        print("\nScanning for open ports on active hosts...")
        for active_ip in active_ips:
            scan_ports(active_ip, ports)
    else:
        print("No active hosts found in the range.")

# Function to ping an IP address and check if it's responsive
def ping_host(ip):
    """
    This function attempts to ping a given IP address to check if the host is up.
    It uses the 'ping' command on the system to check for a response.

    Args:
    - ip (str): The IP address to ping.

    Returns:
    - bool: True if the host responds, False otherwise.
    """
    try:
        # Use the system's ping command to check if the host is reachable
        response = os.system(f"ping -c 1 {ip}")
        # If the response is 0, the host is reachable (ping successful)
        return response == 0
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return False

# Function to run a scan on a specific IP address with a specified range of ports
def scan_single_ip(ip, ports):
    """
    This function runs a complete network scan for a single IP address and specified ports.
    
    Args:
    - ip (str): The IP address to scan.
    - ports (list): A list of port numbers to check on the given IP.

    Returns:
    - None: The results of the scan are printed to the console.
    """
    print(f"Starting scan for {ip}...")
    # Check if the host is reachable before scanning ports
    if ping_host(ip):
        print(f"Host {ip} is reachable. Starting port scan...")
        scan_ports(ip, ports)
    else:
        print(f"Host {ip} is not reachable. Skipping port scan.")

# Multi-threading helper function to scan multiple IPs and ports concurrently
def threaded_scan(ip_range, ports):
    """
    This function uses threading to perform scans on multiple IPs concurrently,
    speeding up the process for larger networks.

    Args:
    - ip_range (str): The subnet or IP range to scan.
    - ports (list): A list of port numbers to check on each IP.

    Returns:
    - None: It initiates the scanning process with threads for each IP.
    """
    print(f"Starting threaded scan for IP range {ip_range}...")
    threads = []  # List to keep track of the thread objects

    # Create a thread for each host in the IP range and start the scanning process
    network = ip_network(ip_range)
    for ip in network.hosts():
        thread = threading.Thread(target=scan_single_ip, args=(str(ip), ports))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

# Main function to set up the scanner and initiate the process
def main():
    """
    This function initializes the network scanner, sets up parameters for the scan,
    and runs the scanning process.
    
    Returns:
    - None: The script prints the results to the console.
    """
    # Define the range of ports to scan
    ports_to_scan = [22, 80, 443, 8080, 3306]  # Example ports: SSH, HTTP, HTTPS, etc.
    
    # Define the IP range or subnet to scan (e.g., '192.168.1.0/24')
    ip_range = input("Enter the IP range or subnet to scan (e.g., '192.168.1.0/24'): ")
    
    # Option to choose between normal or threaded scanning
    scan_type = input("Choose scan type: (1) Normal (2) Threaded: ")
    
    if scan_type == "1":
        # Perform normal scan
        scan_ip_range(ip_range, ports_to_scan)
    elif scan_type == "2":
        # Perform threaded scan for faster execution on large networks
        threaded_scan(ip_range, ports_to_scan)
    else:
        print("Invalid choice. Exiting.")
        return

if __name__ == "__main__":
    start_time = time.time()
    main()
    end_time = time.time()
    print(f"Scanning completed in {end_time - start_time:.2f} seconds.")
