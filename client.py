"""
Client Script for Basic Client-Server Communication

This script creates a TCP client that connects to a server,
sends messages, and receives responses. It demonstrates proper
socket initialization, connection handling, and error management.

Author: Security Automation Course
"""

import socket
import sys


def create_client():
    """
    Creates and configures a TCP client socket.
    
    Returns:
        socket.socket: Configured client socket object.
    """
    try:
        # Create a TCP/IP socket
        # AF_INET: IPv4 address family
        # SOCK_STREAM: TCP protocol (reliable, connection-oriented)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set socket timeout to prevent indefinite blocking
        # This ensures the socket operations will raise an exception if they take too long
        client_socket.settimeout(10)
        
        return client_socket
        
    except socket.error as e:
        print(f"[!] Socket error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error occurred: {e}")
        sys.exit(1)


def connect_to_server(client_socket, host='localhost', port=12345):
    """
    Connects the client socket to the server.
    
    Args:
        client_socket (socket.socket): The client socket to connect.
        host (str): The server hostname or IP address.
        port (int): The server port number.
    
    Returns:
        bool: True if connection successful, False otherwise.
    """
    try:
        print(f"[*] Attempting to connect to {host}:{port}...")
        
        # Attempt to connect to the server
        # This will raise an exception if the connection fails
        client_socket.connect((host, port))
        
        print(f"[+] Successfully connected to {host}:{port}")
        return True
        
    except socket.timeout:
        print(f"[!] Connection timeout: Server at {host}:{port} did not respond")
        return False
    except socket.gaierror as e:
        print(f"[!] Address resolution error: Could not resolve hostname '{host}': {e}")
        return False
    except ConnectionRefusedError:
        print(f"[!] Connection refused: No server listening on {host}:{port}")
        print("[*] Make sure the server is running and the address/port are correct")
        return False
    except socket.error as e:
        print(f"[!] Socket error during connection: {e}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error during connection: {e}")
        return False


def send_message(client_socket, message):
    """
    Sends a message to the server.
    
    Args:
        client_socket (socket.socket): The connected client socket.
        message (str): The message to send.
    
    Returns:
        bool: True if message sent successfully, False otherwise.
    """
    try:
        # Encode the string message to bytes (UTF-8 encoding)
        message_bytes = message.encode('utf-8')
        
        # Send the message to the server
        # sendall() ensures all data is sent (may call send() multiple times)
        client_socket.sendall(message_bytes)
        
        print(f"[*] Sent: {message}")
        return True
        
    except socket.error as e:
        print(f"[!] Error sending message: {e}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error sending message: {e}")
        return False


def receive_response(client_socket):
    """
    Receives a response from the server.
    
    Args:
        client_socket (socket.socket): The connected client socket.
    
    Returns:
        str or None: The received message, or None if an error occurred.
    """
    try:
        # Receive data from the server
        # 1024 is the buffer size (max bytes to receive at once)
        data = client_socket.recv(1024)
        
        # If no data is received, the server has closed the connection
        if not data:
            print("[*] Server closed the connection")
            return None
        
        # Decode the received bytes to string (assuming UTF-8 encoding)
        message = data.decode('utf-8')
        print(f"[*] Received: {message}")
        return message
        
    except socket.timeout:
        print("[!] Receive timeout: Server did not respond in time")
        return None
    except socket.error as e:
        print(f"[!] Socket error while receiving: {e}")
        return None
    except UnicodeDecodeError as e:
        print(f"[!] Error decoding server response: {e}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error while receiving: {e}")
        return None


def run_client(host='localhost', port=12345):
    """
    Main client function that handles the communication loop.
    
    Args:
        host (str): The server hostname or IP address.
        port (int): The server port number.
    """
    client_socket = None
    
    try:
        # Create the client socket
        client_socket = create_client()
        
        # Connect to the server
        if not connect_to_server(client_socket, host, port):
            return
        
        print("\n[*] Type messages to send to the server")
        print("[*] Type 'quit' to disconnect\n")
        
        # Communication loop
        while True:
            try:
                # Get user input
                message = input("Enter message: ").strip()
                
                # Check for empty input
                if not message:
                    print("[!] Empty message. Please enter a message.")
                    continue
                
                # Send the message
                if not send_message(client_socket, message):
                    break
                
                # Check for quit command
                if message.lower() == 'quit':
                    print("[*] Disconnecting from server...")
                    break
                
                # Receive and display server response
                response = receive_response(client_socket)
                if response is None:
                    break
                    
            except KeyboardInterrupt:
                print("\n[*] Interrupted by user")
                break
            except EOFError:
                print("\n[*] End of input")
                break
            except Exception as e:
                print(f"[!] Unexpected error: {e}")
                break
                
    except KeyboardInterrupt:
        print("\n[*] Client interrupted by user")
    except Exception as e:
        print(f"[!] Unexpected client error: {e}")
    finally:
        # Always close the socket when done
        if client_socket:
            client_socket.close()
            print("[*] Client socket closed")


if __name__ == "__main__":
    """
    Entry point for the client script.
    Allows customization of server host and port via command-line arguments.
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
    
    # Start the client
    run_client(host, port)

