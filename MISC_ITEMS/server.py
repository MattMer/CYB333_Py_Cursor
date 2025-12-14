"""
Server Script for Basic Client-Server Communication

This script creates a TCP server that listens for incoming connections
on a specified host and port. It handles client connections, receives
messages, and sends responses back to clients.

Author: Security Automation Course
"""

import socket
import sys


def create_server(host='localhost', port=12345):
    """
    Creates and configures a TCP server socket.
    
    Args:
        host (str): The hostname or IP address to bind to. 
                   Use 'localhost' or '127.0.0.1' for local connections,
                   or '' to accept connections from any interface.
        port (int): The port number to listen on (1024-65535).
    
    Returns:
        socket.socket: Configured server socket object.
    """
    try:
        # Create a TCP/IP socket
        # AF_INET: IPv4 address family
        # SOCK_STREAM: TCP protocol (reliable, connection-oriented)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set socket option to reuse address (prevents "Address already in use" error)
        # SO_REUSEADDR allows the socket to reuse a local address that's in TIME_WAIT state
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind the socket to the host and port
        # This associates the socket with a specific network interface and port
        server_socket.bind((host, port))
        
        # Enable the server to accept connections
        # The argument (5) specifies the maximum number of queued connections
        server_socket.listen(5)
        
        print(f"[*] Server listening on {host}:{port}")
        print("[*] Waiting for connections...")
        
        return server_socket
        
    except socket.error as e:
        print(f"[!] Socket error occurred: {e}")
        sys.exit(1)
    except OSError as e:
        print(f"[!] OS error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error occurred: {e}")
        sys.exit(1)


def handle_client(client_socket, client_address):
    """
    Handles communication with a connected client.
    
    Args:
        client_socket (socket.socket): The socket object for the client connection.
        client_address (tuple): Tuple containing (host, port) of the client.
    """
    print(f"[+] Connection established with {client_address[0]}:{client_address[1]}")
    
    try:
        while True:
            # Receive data from the client
            # 1024 is the buffer size (max bytes to receive at once)
            data = client_socket.recv(1024)
            
            # If no data is received, the client has closed the connection
            if not data:
                print(f"[*] Client {client_address[0]}:{client_address[1]} disconnected")
                break
            
            # Decode the received bytes to string (assuming UTF-8 encoding)
            message = data.decode('utf-8')
            print(f"[*] Received from {client_address[0]}: {message}")
            
            # Check for quit command
            if message.lower().strip() == 'quit':
                print(f"[*] Client {client_address[0]}:{client_address[1]} requested disconnect")
                break
            
            # Prepare response message
            response = f"Server received: {message}"
            
            # Send response back to client
            # encode() converts string to bytes for transmission
            client_socket.sendall(response.encode('utf-8'))
            print(f"[*] Sent response to {client_address[0]}: {response}")
            
    except socket.error as e:
        print(f"[!] Socket error while handling client: {e}")
    except UnicodeDecodeError as e:
        print(f"[!] Error decoding message: {e}")
    except Exception as e:
        print(f"[!] Unexpected error while handling client: {e}")
    finally:
        # Always close the client socket when done
        client_socket.close()
        print(f"[*] Connection with {client_address[0]}:{client_address[1]} closed")


def run_server(host='localhost', port=12345):
    """
    Main server loop that accepts and handles client connections.
    
    Args:
        host (str): The hostname or IP address to bind to.
        port (int): The port number to listen on.
    """
    server_socket = None
    
    try:
        # Create and configure the server socket
        server_socket = create_server(host, port)
        
        # Main server loop - continuously accept connections
        while True:
            try:
                # Accept a connection
                # This blocks until a client connects
                # Returns a new socket for the client and the client's address
                client_socket, client_address = server_socket.accept()
                
                # Handle the client connection
                handle_client(client_socket, client_address)
                
            except KeyboardInterrupt:
                # Handle Ctrl+C gracefully
                print("\n[*] Server shutdown requested by user")
                break
            except socket.error as e:
                print(f"[!] Error accepting connection: {e}")
                continue
                
    except KeyboardInterrupt:
        print("\n[*] Server shutdown requested by user")
    except Exception as e:
        print(f"[!] Unexpected server error: {e}")
    finally:
        # Always close the server socket when shutting down
        if server_socket:
            server_socket.close()
            print("[*] Server socket closed")


if __name__ == "__main__":
    """
    Entry point for the server script.
    Allows customization of host and port via command-line arguments.
    """
    # Default values
    host = 'localhost'
    port = 12345
    
    # Parse command-line arguments if provided
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
            if not (1024 <= port <= 65535):
                print("[!] Port must be between 1024 and 65535")
                sys.exit(1)
        except ValueError:
            print("[!] Port must be a valid integer")
            sys.exit(1)
    
    # Start the server
    run_server(host, port)

