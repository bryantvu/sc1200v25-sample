
import socket

SOCKET_TIMEOUT = 1.5

def scan_ip_ports(ip_list, ports=[5000, 5001,5002, 9750], timeout=0.5):
    """
    Attempts to open TCP connections to common Waveshare and XBee ports.
    Returns list of reachable (ip:port) strings.
    """
    valid_endpoints = []
    for ip in ip_list:
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    print(f"Found open port at {ip}:{port}")
                    valid_endpoints.append(f"{ip}:{port}")
            except Exception:
                print(f"could not open port at {ip}:{port}")
                pass  # Silent fail for closed ports
    return valid_endpoints

def discover_waveshare_devices(port=10000, timeout=SOCKET_TIMEOUT):
    """
    Sends a UDP 'FIND' to discover Waveshare modules.
    Returns a list of responsive IPs.
    """
    discovered_ips = set()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(b'FIND', ('<broadcast>', port))

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                discovered_ips.add(addr[0])
                print(f"Waveshare responded: {addr[0]} → {data}")
            except socket.timeout:
                break
    except Exception as e:
        print(f"UDP discovery error: {e}")
    finally:
        sock.close()
    return list(discovered_ips)


def find_xbee_and_waveshare_devices(user_ips=None, user_ports=None):
    xbee_ips = user_ips if user_ips else ["192.168.1.10", "192.168.1.125", "192.168.1.126", "192.168.1.127"]
    ips = discover_waveshare_devices()
    ips.extend(xbee_ips)

    ports = user_ports if user_ports else [5000, 5001, 5002, 9750]
    return scan_ip_ports(ips, ports=ports)

"""
def find_xbee_and_waveshare_devices():
    
    Combined discovery for both Waveshare (UDP) and XBee (TCP scan).
    Returns list of reachable 'ip:port' endpoints.
    
    xbee_ips = ["192.168.1.10","192.168.1.125","192.168.1.126", "192.168.1.127"]
    ips = discover_waveshare_devices()
    ips.extend(xbee_ips)

    return scan_ip_ports(ips)
"""