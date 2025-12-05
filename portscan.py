import socket

def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((host, port))
        return True
    except:
        return False
    finally:
        s.close()

def scan_host(host, ports):
    print(f"Scanning {host}...")
    for port in ports:
        if scan_port(host, port):
            print(f"[+] Port {port} open")
        else:
            print(f"[-] Port {port} closed")

if __name__ == "__main__":
    # Example: scan a device on your network
    target_host = "192.168.1.50"   # Change to a real device on your LAN
    common_ports = [21, 22, 80, 139, 445, 3389]

    scan_host(target_host, common_ports)
