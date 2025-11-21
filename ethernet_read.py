import socket

# Set the IP address and port of your Ethernet device
DEVICE_IP = '192.168.1.200'  # Replace with your actual device IP
DEVICE_PORT = 5002           # Replace with your device's port

def read_from_ethernet():
    try:
        # Create a TCP socket
        print(f"Trying to connect {DEVICE_IP}:{DEVICE_PORT}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(100)  # 100-second timeout for recv()
            s.connect((DEVICE_IP, DEVICE_PORT))
            print(f"Connected to {DEVICE_IP}:{DEVICE_PORT}")

            # Send a sample command (optional)
            command = "CID<CR>"  # Replace with actual command and format
            s.sendall(command.replace("<CR>", "\r").encode())
            data = s.recv(1024)
            if data:
                received = data.decode(errors="ignore")
                print("Received:", received)
                payload = parse_response(received)
                print("payload:", payload)
            else:
                print("No data received.")
            
    except Exception as e:
        print(f"Connection failed {DEVICE_IP}:{DEVICE_PORT}")
        print(f"Error: {e}")

def parse_response(response_bytes):
    """
    Parses the response of the form:
    <STX><payload>*<checksum><ETX>
    where:
        - <STX> is X02
        - <ETX> is X03
    
    Returns:
        payload (str): The parsed payload if valid, else None
    """
    response_bytes = response_bytes.strip()
    # Check if response starts with ASCII characters: x, 0, 2
    if not response_bytes.startswith('X02'):
        print("'X02' not found at start")
        return None
    print("Detected literal 'X02' at start — skipping first 3 bytes")
    # Strip 'x02' (3 characters)
    trimmed_stx = response_bytes[3:]
    
    # Expect real start and end delimiters (STX and ETX)
    if not trimmed_stx.endswith('X03'):
        print("Missing ETX delimiters")
        return None
    # Strip STX and ETX
    trimmed = trimmed_stx[:-3]
    print("trimmed:",trimmed)

    # Split payload and checksum
    try:
        payload_part, checksum_hex = trimmed.rsplit('*', 1)
    except ValueError:
        print("Malformed response: '*' separator missing")
        return None
    print("payload_part:", payload_part)
    print("received chk sum:", checksum_hex)
    # Compute XOR checksum
    checksum_calc = 0
    for ch in payload_part:
        checksum_calc ^= ord(ch)
    
    computed_hex = f"{checksum_calc:02X}"
    print("computed chksum hex:", computed_hex)

    # Verify checksum
    if checksum_hex != computed_hex:
        print(f"Checksum mismatch! Expected {checksum_hex}, got {computed_hex}")
        return None

    return payload_part


if __name__ == "__main__":
    read_from_ethernet()
