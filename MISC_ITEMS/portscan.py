"""
Port Scanner - Security Automation Tool

This script provides a comprehensive port scanning utility that can:
- Scan a specified range of ports on a target host
- Identify open ports
- Handle connections appropriately with proper error handling
- Follow Python best practices with comprehensive documentation

Author: Security Automation Course
"""

import socket
import sys
import argparse
import errno
from typing import List, Tuple, Optional


# Common ports relevant to cybersecurity scanning
# These ports are frequently targeted in security assessments
COMMON_PORTS = [
    21,      # FTP (File Transfer Protocol)
    22,      # SSH (Secure Shell)
    23,      # Telnet
    25,      # SMTP (Simple Mail Transfer Protocol)
    53,      # DNS (Domain Name System)
    80,      # HTTP (Hypertext Transfer Protocol)
    110,     # POP3 (Post Office Protocol)
    135,     # RPC (Remote Procedure Call)
    139,     # NetBIOS Session Service
    143,     # IMAP (Internet Message Access Protocol)
    443,     # HTTPS (HTTP Secure)
    445,     # SMB (Server Message Block)
    993,     # IMAPS (IMAP over SSL)
    995,     # POP3S (POP3 over SSL)
    1433,    # MSSQL (Microsoft SQL Server)
    3306,    # MySQL
    3389,    # RDP (Remote Desktop Protocol)
    5432,    # PostgreSQL
    5900,    # VNC (Virtual Network Computing)
    8080,    # HTTP-Proxy (Alternative HTTP)
    8443,    # HTTPS-Proxy (Alternative HTTPS)
]


def get_common_ports() -> List[int]:
    """
    Returns a list of common ports relevant to cybersecurity scanning.
    
    These ports are frequently targeted in security assessments and penetration testing
    as they often host services that may be misconfigured or vulnerable.
    
    Returns:
        List[int]: Sorted list of common cybersecurity-relevant port numbers
    """
    return sorted(COMMON_PORTS.copy())


def parse_port_range(port_input: str) -> List[int]:
    """
    Parses a port range string into a list of port numbers.
    
    Supports multiple formats:
    - Single port: "80"
    - Range: "1-1000"
    - Multiple ports/ranges: "80,443,8080-8090"
    
    Args:
        port_input (str): Port specification string (e.g., "80", "1-1000", "80,443,8080-8090")
    
    Returns:
        List[int]: Sorted list of unique port numbers to scan
    
    Raises:
        ValueError: If the port input format is invalid or ports are out of range
    """
    ports = []
    
    # Split by comma to handle multiple port specifications
    port_specs = port_input.split(',')
    
    for spec in port_specs:
        spec = spec.strip()
        
        # Check if it's a range (contains hyphen)
        if '-' in spec:
            try:
                start, end = spec.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                # Validate port range
                if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                    raise ValueError(f"Ports must be between 1 and 65535")
                
                if start_port > end_port:
                    raise ValueError(f"Start port ({start_port}) cannot be greater than end port ({end_port})")
                
                # Add all ports in the range
                ports.extend(range(start_port, end_port + 1))
                
            except ValueError as e:
                if "Ports must be" in str(e) or "cannot be greater" in str(e):
                    raise
                raise ValueError(f"Invalid port range format: '{spec}'. Use format 'start-end' (e.g., '1-1000')")
        else:
            # Single port
            try:
                port = int(spec)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port must be between 1 and 65535, got {port}")
                ports.append(port)
            except ValueError as e:
                if "Port must be" in str(e):
                    raise
                raise ValueError(f"Invalid port number: '{spec}'. Port must be an integer between 1 and 65535")
    
    # Remove duplicates and sort
    return sorted(list(set(ports)))


def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Scans a single port on the target host.
    
    Attempts to establish a TCP connection to the specified port.
    If the connection succeeds, the port is considered open.
    
    Args:
        host (str): Target hostname or IP address
        port (int): Port number to scan (1-65535)
        timeout (float): Connection timeout in seconds (default: 1.0)
    
    Returns:
        Tuple[bool, Optional[str], Optional[str]]: 
            - First element: True if port is open, False otherwise
            - Second element: Error message if connection failed, None if successful
            - Third element: "unreachable" if host is unreachable, None otherwise
    """
    # Create a TCP socket
    # AF_INET: IPv4 address family
    # SOCK_STREAM: TCP protocol (reliable, connection-oriented)
    sock = None
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set socket timeout to prevent indefinite blocking
        # This ensures the connection attempt will raise an exception if it takes too long
        sock.settimeout(timeout)
        
        # Attempt to connect to the target host and port
        # connect_ex() returns 0 on success, error code on failure
        result = sock.connect_ex((host, port))
        
        # connect_ex() returns 0 on success, error code on failure
        if result == 0:
            return True, None, None
        
        # Check for unreachable host error codes
        # Windows error codes: 10051 (Network is unreachable), 10065 (No route to host)
        # Linux/Unix error codes: errno.ENETUNREACH, errno.EHOSTUNREACH
        unreachable_codes = [
            errno.ENETUNREACH,      # Network is unreachable
            errno.EHOSTUNREACH,     # No route to host
            10051,                  # Windows: Network is unreachable
            10065,                  # Windows: No route to host
        ]
        
        if result in unreachable_codes:
            return False, f"Host unreachable (error code: {result})", "unreachable"
        else:
            return False, f"Connection failed (error code: {result})", None
    
    except socket.timeout:
        # Connection attempt timed out (port is likely filtered or closed)
        # Note: Timeout alone doesn't indicate unreachability
        return False, "Connection timeout", None
    
    except socket.gaierror as e:
        # DNS resolution failed (invalid hostname)
        return False, f"DNS resolution failed: {e}", "unreachable"
    
    except ConnectionRefusedError:
        # Connection was refused (port is closed, but host is reachable)
        return False, "Connection refused", None
    
    except OSError as e:
        # Network-related errors
        error_code = e.errno if hasattr(e, 'errno') else None
        
        # Check for unreachable host error codes
        unreachable_codes = [
            errno.ENETUNREACH,      # Network is unreachable
            errno.EHOSTUNREACH,     # No route to host
            10051,                  # Windows: Network is unreachable
            10065,                  # Windows: No route to host
        ]
        
        if error_code in unreachable_codes:
            return False, f"Host unreachable: {e}", "unreachable"
        else:
            return False, f"Network error: {e}", None
    
    except Exception as e:
        # Catch any other unexpected errors
        return False, f"Unexpected error: {e}", None
    
    finally:
        # Always close the socket to free system resources
        # This is critical to prevent resource leaks
        if sock:
            try:
                sock.close()
            except Exception:
                # Ignore errors during socket closure
                pass


def scan_host(host: str, ports: List[int], timeout: float = 1.0, verbose: bool = False) -> dict:
    """
    Scans multiple ports on a target host.
    
    Args:
        host (str): Target hostname or IP address
        ports (List[int]): List of port numbers to scan
        timeout (float): Connection timeout in seconds for each port
        verbose (bool): If True, print status for all ports. If False, only print open ports.
    
    Returns:
        dict: Dictionary containing scan results with keys:
            - 'open_ports': List of open port numbers
            - 'closed_ports': List of closed port numbers
            - 'total_scanned': Total number of ports scanned
            - 'host_unreachable': Boolean indicating if host is unreachable
    """
    print(f"\n[*] Starting port scan on {host}")
    print(f"[*] Scanning {len(ports)} port(s)...")
    print(f"[*] Timeout: {timeout} seconds per port\n")
    
    open_ports = []
    closed_ports = []
    host_unreachable = False
    unreachable_errors = []
    
    # Scan each port in the list
    for i, port in enumerate(ports, 1):
        try:
            # Scan the port
            is_open, error_msg, unreachable_status = scan_port(host, port, timeout)
            
            # Check if host is unreachable
            if unreachable_status == "unreachable":
                host_unreachable = True
                unreachable_errors.append((port, error_msg))
                # Don't add to closed ports - host is unreachable, not port closed
                if i == 1 or verbose:
                    # Show error on first port or in verbose mode
                    print(f"[!] Port {port:5d}: Host unreachable ({error_msg})")
                continue
            
            if is_open:
                # Port is open - add to results and print
                open_ports.append(port)
                print(f"[+] Port {port:5d} is OPEN")
            else:
                # Port is closed or filtered (host is reachable)
                closed_ports.append(port)
                if verbose:
                    # Only print closed ports if verbose mode is enabled
                    print(f"[-] Port {port:5d} is CLOSED ({error_msg})")
            
            # Progress indicator for large scans
            if i % 100 == 0:
                print(f"[*] Progress: {i}/{len(ports)} ports scanned...")
        
        except KeyboardInterrupt:
            # Handle user interruption gracefully
            print(f"\n[!] Scan interrupted by user after {i-1} ports")
            break
        
        except Exception as e:
            # Handle unexpected errors during scanning
            print(f"[!] Error scanning port {port}: {e}")
            closed_ports.append(port)
    
    # Print scan summary
    print(f"\n{'='*60}")
    print(f"Scan Summary:")
    print(f"  Target Host: {host}")
    
    # Check if host is unreachable
    if host_unreachable:
        print(f"  Status: HOST UNREACHABLE")
        print(f"  [!] The target host appears to be unreachable.")
        print(f"  [!] This could mean:")
        print(f"      - The host is down or not responding")
        print(f"      - Network routing issues")
        print(f"      - Firewall blocking all connections")
        print(f"      - Invalid hostname or IP address")
        print(f"  [!] Port status cannot be determined for unreachable hosts.")
    else:
        print(f"  Status: Host is reachable")
        print(f"  Total Ports Scanned: {len(open_ports) + len(closed_ports)}")
        print(f"  Open Ports: {len(open_ports)}")
        print(f"  Closed/Filtered Ports: {len(closed_ports)}")
        
        # Display open ports list
        if open_ports:
            print(f"\n  Open Ports List: {', '.join(map(str, open_ports))}")
        else:
            print(f"\n  No open ports found.")
        
        # Display closed ports list
        if closed_ports:
            print(f"\n  Closed Ports List: {', '.join(map(str, closed_ports))}")
        else:
            print(f"\n  No closed ports found.")
    
    print(f"{'='*60}\n")
    
    return {
        'open_ports': open_ports,
        'closed_ports': closed_ports,
        'total_scanned': len(open_ports) + len(closed_ports),
        'host_unreachable': host_unreachable
    }


def main():
    """
    Main entry point for the port scanner.
    
    Parses command-line arguments and initiates the port scan.
    """
    # Create argument parser with description
    parser = argparse.ArgumentParser(
        description='Port Scanner - Scan ports on a target host',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan common cybersecurity ports
  python portscan.py localhost --common
  
  # Scan a single port
  python portscan.py localhost 80
  
  # Scan common ports plus additional ports
  python portscan.py 192.168.1.1 8080,8443 --common
  
  # Scan a range of ports
  python portscan.py 192.168.1.1 1-1000
  
  # Scan multiple ports and ranges
  python portscan.py example.com 80,443,8080-8090
  
  # Verbose mode (show closed ports)
  python portscan.py localhost 1-100 -v
  
  # Common ports with custom timeout
  python portscan.py localhost --common -t 0.5
        """
    )
    
    # Required arguments
    parser.add_argument('host', 
                       help='Target hostname or IP address to scan')
    parser.add_argument('ports', 
                       nargs='?',  # Make ports optional
                       default=None,
                       help='Port(s) to scan. Can be: single port (80), range (1-1000), or comma-separated (80,443,8080-8090). Optional if --common is used.')
    
    # Optional arguments
    parser.add_argument('-c', '--common', 
                       action='store_true',
                       help='Scan common cybersecurity-relevant ports (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443)')
    parser.add_argument('-t', '--timeout', 
                       type=float, 
                       default=1.0,
                       help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-v', '--verbose', 
                       action='store_true',
                       help='Show detailed output including closed ports')
    
    # Parse command-line arguments
    args = parser.parse_args()
    
    # Validate timeout
    if args.timeout <= 0:
        print("[!] Error: Timeout must be greater than 0")
        sys.exit(1)
    
    # Check if at least one port specification method is provided
    if not args.common and not args.ports:
        print("[!] Error: Must specify either ports to scan or use --common flag")
        print("[*] Use --help for usage examples")
        sys.exit(1)
    
    try:
        port_list = []
        
        # Add common ports if --common flag is used
        if args.common:
            common_ports = get_common_ports()
            port_list.extend(common_ports)
            print(f"[*] Including {len(common_ports)} common cybersecurity ports")
        
        # Add user-specified ports if provided
        if args.ports:
            parsed_ports = parse_port_range(args.ports)
            port_list.extend(parsed_ports)
            if args.common:
                print(f"[*] Including {len(parsed_ports)} user-specified port(s)")
        
        # Remove duplicates and sort
        port_list = sorted(list(set(port_list)))
        
        if not port_list:
            print("[!] Error: No valid ports to scan")
            sys.exit(1)
        
        # Perform the port scan
        results = scan_host(args.host, port_list, args.timeout, args.verbose)
        
        # Exit with appropriate code
        # 0 if open ports found
        # 1 if no open ports but host is reachable
        # 2 if host is unreachable
        if results['host_unreachable']:
            sys.exit(2)
        elif results['open_ports']:
            sys.exit(0)
        else:
            sys.exit(1)
    
    except ValueError as e:
        # Handle invalid port specifications
        print(f"[!] Error: {e}")
        sys.exit(1)
    
    except KeyboardInterrupt:
        # Handle user interruption
        print("\n[!] Scan interrupted by user")
        sys.exit(130)  # Standard exit code for SIGINT
    
    except Exception as e:
        # Handle unexpected errors
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
