from serial import SerialException, EIGHTBITS, PARITY_NONE, STOPBITS_ONE
from serial.tools.list_ports import comports
from serial import serial_for_url
import time

INVALID_DATA = ["", "A", "E"]

class SerialNotOpenException(Exception):
    pass

class Comport:
    def __init__(self, port):
        self.port = port
        self.serialport = None
        self.baudrate = 9600
        self.addr64 = None  # Zigbee 64-bit address
        self.addr16 = None
        self.is_zigbee = False

    def open(self):
        try:
            port_url = (
                f"socket://{self.port}" if ':' in self.port and not self.port.startswith("socket://")
                else self.port
            )
            print(f"[DEBUG] Attempting to open: {port_url}")
            try:
                self.serialport = serial_for_url(port_url, baudrate=self.baudrate, timeout=5)
                print(f"[DEBUG] Successfully opened: {port_url}")
            except Exception as e:
                print(f"[ERROR] Failed to open {port_url} → {e}")
                raise
            if port_url.startswith("COM") or port_url.startswith("/dev/"):
                self._set_serial_settings()

        except SerialException as e:
            print(f"[ERROR] Could not open comport {self.port}\n\t{e}")

    def _set_serial_settings(self):
        self.serialport.bytesize = EIGHTBITS
        self.serialport.parity = PARITY_NONE
        self.serialport.stopbits = STOPBITS_ONE
        self.serialport.timeout = 5
        self.serialport.xonxoff = False
        self.serialport.rtscts = False
        self.serialport.dsrdtr = False
        self.serialport.writeTimeout = 2

    def close(self):
        if self.serialport and self.serialport.is_open:
            self.serialport.close()


    @staticmethod
    def find_all_ports(replace=True):
        ports = [port.device for port in comports()]
        if replace:
            print(f"[DEBUG] Found COM ports: {ports}")
        return ports
    
    def test_connection(self) -> bool:
            """
            Tests the connection of the sensor
            :return: A
            """
            count = 0
            while True:
                try:
                    self._send_command("")
                    response = self._read_line()
                    if response == "A":
                        return True
                    return False
                except SerialNotOpenException:
                    if count == 3:
                        return False
                    count += 1  

# private functions
    @staticmethod
    def _connected_comports() -> [object]:
        """
        Discovers connected comports regardless of operating system
        :return: a list of comport objects
        """
        return sorted(comports())

    def _send_command(self, command: str):
        if self.serialport.is_open:
            self.serialport.write((command + '\r').encode('utf-8'))
            self.serialport.flush()
            print(f"[DEBUG] write the command to the port")
        else:
            raise SerialNotOpenException("Failed to write command: port not open")

    def _read_line(self) -> str:
        if self.serialport.is_open:
            response = self.serialport.readline().decode("utf-8").strip()
            self.serialport.flush()
            print(f"[DEBUG] read the line")
            return response
        else:
            raise SerialNotOpenException("Failed to read line: port not open")

    def _read_multiple_responses(self, timeout_seconds=5.0, max_responses=12, response_gap=0.5) -> list:
        """
        Reads multiple responses from the serial port until timeout or max responses reached.
        
        Args:
            timeout_seconds: Maximum time to wait for responses (default 3.0 seconds)
            max_responses: Maximum number of responses to collect (default 12 for SC1200 ports)
            response_gap: Time in seconds with no new responses before considering complete (default 0.3)
        
        Returns:
            List of response strings, excluding invalid responses
        """
        if not self.serialport.is_open:
            raise SerialNotOpenException("Failed to read responses: port not open")
        
        responses = []
        start_time = time.time()
        last_response_time = None
        
        print(f"[DEBUG] Starting multi-response read (timeout={timeout_seconds}s, max={max_responses})")
        
        while True:
            current_time = time.time()
            elapsed = current_time - start_time
            
            # Check if we've exceeded the timeout
            if elapsed >= timeout_seconds:
                print(f"[DEBUG] Timeout reached after {elapsed:.2f}s, collected {len(responses)} responses")
                break
            
            # Check if we've reached max responses
            if len(responses) >= max_responses:
                print(f"[DEBUG] Max responses ({max_responses}) reached")
                break
            
            # Check if we've had a gap with no new responses (adaptive completion)
            if last_response_time is not None:
                gap = current_time - last_response_time
                if gap >= response_gap:
                    print(f"[DEBUG] Response gap of {gap:.2f}s detected, collected {len(responses)} responses")
                    break
            
            # Try to read a line (non-blocking with timeout)
            try:
                # Set a short timeout for individual reads
                original_timeout = self.serialport.timeout
                self.serialport.timeout = 0.1  # Short timeout for non-blocking check
                
                line = self.serialport.readline()
                
                # Restore original timeout
                self.serialport.timeout = original_timeout
                
                if line:
                    try:
                        response = line.decode("utf-8").strip()
                        if response and not self._invalid_data(response):
                            responses.append(response)
                            last_response_time = current_time
                            print(f"[DEBUG] Collected response {len(responses)}: {response[:50]}...")
                        else:
                            print(f"[DEBUG] Skipped invalid response: {response}")
                    except UnicodeDecodeError:
                        print(f"[DEBUG] Skipped non-UTF8 response")
                else:
                    # No data available, sleep briefly to avoid CPU spinning
                    time.sleep(0.01)
                    
            except Exception as e:
                print(f"[DEBUG] Error reading response: {e}")
                time.sleep(0.01)
        
        print(f"[DEBUG] Multi-response read complete: {len(responses)} valid responses")
        return responses
        
    def _read_byte(self, num_of_bytes) -> bytes:
        if self.serialport.is_open:
            byte = self.serialport.read(num_of_bytes)  # Read a single byte
            self.serialport.flush()
            if byte:
                print(f"[DEBUG] Read byte: {byte.hex().upper()}")
            else:
                print("[DEBUG] No byte read (timeout or empty buffer)")
            return byte
        else:
            raise SerialNotOpenException("Failed to read byte: port not open")


    def _send_command_get_response(self, command: str, default_response: str, multi_response: bool = False, max_responses: int = 12) -> str:
        """
        Sends a command and gets response(s).
        
        Args:
            command: Command string to send
            default_response: Default response if invalid or no response
            multi_response: If True, read multiple responses (for SC1200 multi-port commands)
            max_responses: Maximum number of responses to read when multi_response=True
        
        Returns:
            Single response string if multi_response=False, or first valid response if multi_response=True
            (Note: For multi-response, use _send_command_get_multiple_responses() instead)
        """
        '''
        if self.serialport and self.serialport.is_open:
            self.serialport.reset_input_buffer()
            time.sleep(0.01)
        '''
        self._send_command(command)
        if multi_response:
            responses = self._read_multiple_responses(max_responses=max_responses)
            if responses:
                return responses[0]  # Return first response for backward compatibility
            return default_response
        else:
            response = self._read_line()
            if self._invalid_data(response):
                print(f"[DEBUG] Invalid response")
                return default_response
            return response

    def _send_command_get_multiple_responses(self, command: str, max_responses: int = 12, timeout_seconds: float = 5.0) -> list:
        """
        Sends a command to all ports and gets all responses (for SC1200 multi-port commands).
        For SC1200, commands must include port numbers, so we send to all 12 ports in quick succession.
        
        Args:
            command: Command base (e.g., "SNM", "WGHT", "SINF") - port numbers will be added
            max_responses: Maximum number of responses to read (default 12 for SC1200 ports)
            timeout_seconds: Maximum time to wait for responses
        
        Returns:
            List of response strings
        """
        if self.serialport and self.serialport.is_open:
            self.serialport.reset_input_buffer()
            time.sleep(0.01)
        
        # SC1200 requires port numbers in commands, so send to all 12 ports in quick succession
        # Send all commands first without waiting for responses
        print(f"[DEBUG] Sending {command} command to all 12 ports...")
        for port_num in range(1, 13):
            port_command = f"{command} P{port_num} "
            self._send_command(port_command)
            time.sleep(0.01)  # Small delay between commands to avoid overwhelming the device
        
        # Now read all responses that come back
        print(f"[DEBUG] Reading responses from all ports...")
        return self._read_multiple_responses(timeout_seconds=timeout_seconds, max_responses=max_responses)
    
    def _set_baudrate(self):
        """
        Tries the available baudrates to see if they work with the sensors
        :return: successful connection as a boolean
        """
        for baudrate in [9600, 230400]:
            self.serialport.baudrate = baudrate
            self.baudrate = 9600
            self.open()
            if self.test_connection():
                self.close()
                return True
            self.close()
        return False

    @staticmethod
    def _invalid_data(data: str) -> bool:
        if type(data) != str or data in INVALID_DATA:
            return True
        return False



    def get_cid(self):
        
        if self.serialport and self.serialport.is_open:
            time.sleep(0.05)
            self.serialport.reset_input_buffer()
            self.serialport.reset_output_buffer()
            time.sleep(0.05)
        #command = ('CID' + '\r').encode('utf-8')
        if self.is_zigbee and self.addr64:
            print(f"[DEBUG] Sending Zigbee CID to {self.addr64}")
            frame = self.build_zigbee_tx_frame(self.addr64, "CID\r\n")
            self.serialport.write(frame)
            #time.sleep(0.05)
            self.serialport.flush()
            start_time = time.time()
            while time.time() - start_time < 2:
                frame = self.read_api_frame()
                parsed = self.parse_xbee_frame(frame)
                if parsed and parsed['type'] == 'RX':
                    return parsed['data']
            return "--"
        else:
            print(f"[DEBUG] Sending COM {self.serialport} CID")
            return self._send_command_get_response(command="CID", default_response="--")

    def build_zigbee_tx_frame(self, addr64_hexstr, data_str):
        addr64_bytes = bytes.fromhex(addr64_hexstr.replace(':', ''))
        frame_id = 0x01
        addr16 = b'\xFF\xFE'
        broadcast_radius = 0x00
        options = 0x00
        rf_data = data_str.encode()

        frame_data = (
            bytes([0x10, frame_id]) +
            addr64_bytes +
            addr16 +
            bytes([broadcast_radius, options]) +
            rf_data
        )

        length = len(frame_data)
        checksum = 0xFF - (sum(frame_data) & 0xFF)
        frame = bytes([0x7E]) + length.to_bytes(2, 'big') + frame_data + bytes([checksum])
        return frame

    def __getattr__(self, name):
        if name.startswith("get_"):
            def zigbee_wrapper(portnum=None, broadcast=False):
                """
                Wrapper for get_* methods.
                
                Args:
                    portnum: Port number (1-12). If None and broadcast=False, defaults to 1 for backward compatibility.
                    broadcast: If True, send broadcast command without port number to get all 12 port responses.
                              Returns list of responses instead of single response.
                
                Returns:
                    Single response string if broadcast=False, or list of responses if broadcast=True
                """
                cmd_base = name[4:].upper()
                
                # Determine command format
                if broadcast or portnum is None:
                    # Broadcast command - no port number, device responds with all ports
                    cmd = cmd_base + " "
                    print(f"[DEBUG] Sending broadcast {cmd_base} command (expecting multiple responses)")
                else:
                    # Single port command
                    cmd = cmd_base + f" P{portnum} "
                    print(f"[DEBUG] Sending {cmd_base} command for port {portnum}")
                
                if self.is_zigbee and self.addr64:
                    if broadcast or portnum is None:
                        # For Zigbee broadcast, we need to read multiple responses
                        print(f"[DEBUG] Sending Zigbee broadcast command: {cmd} to {self.addr64}")
                        frame = self.build_zigbee_tx_frame(self.addr64, cmd)
                        self.serialport.write(frame)
                        self.serialport.flush()
                        
                        responses = []
                        start_time = time.time()
                        last_response_time = None
                        response_gap = 0.3
                        
                        while time.time() - start_time < 3.0 and len(responses) < 12:
                            frame = self.read_api_frame()
                            if frame:
                                parsed = self.parse_xbee_frame(frame)
                                if parsed and parsed['type'] == 'RX':
                                    response = parsed['data']
                                    if response and not self._invalid_data(response):
                                        responses.append(response)
                                        last_response_time = time.time()
                                        print(f"[DEBUG] Collected Zigbee response {len(responses)}: {response[:50]}")
                            
                            # Check for response gap
                            if last_response_time and (time.time() - last_response_time) >= response_gap:
                                break
                            
                            time.sleep(0.01)
                        
                        return responses if broadcast else (responses[0] if responses else "--")
                    else:
                        # Single port Zigbee command
                        print(f"[DEBUG] Sending Zigbee command: {cmd} to {self.addr64}")
                        frame = self.build_zigbee_tx_frame(self.addr64, cmd)
                        self.serialport.write(frame)
                        self.serialport.flush()
                        start_time = time.time()
                        while time.time() - start_time < 2:
                            frame = self.read_api_frame()
                            parsed = self.parse_xbee_frame(frame)
                            if parsed and parsed['type'] == 'RX':
                                return parsed['data']
                        return "--"
                else:
                    # Serial/Ethernet command
                    if broadcast or (portnum is None and cmd_base in ['WGHT', 'W', 'SNM', 'SINF', 'SLC', 'UNIT', 'TYPE']):
                        # For SC1200, send command to all 12 ports and collect all responses
                        print(f"[DEBUG] Sending {cmd_base} command to all ports (multi-response mode)")
                        responses = self._send_command_get_multiple_responses(command=cmd_base, max_responses=12)
                        return responses if broadcast else (responses[0] if responses else "--")
                    else:
                        # Single port command (backward compatibility)
                        if portnum is None:
                            portnum = 1  # Default to port 1 for backward compatibility
                        cmd = cmd_base + f" P{portnum} "
                        print(f"[DEBUG] Sending COM command: {cmd}")
                        return self._send_command_get_response(command=cmd, default_response="--")
            
            return zigbee_wrapper
        raise AttributeError(f"{name} not found")

    # Existing methods like open, close, _send_command_get_response, read_api_frame, parse_xbee_frame, etc.
    # should be preserved in your original file.

    def discover_xbee_nodes(self):
        """
        Sends ND command to discover all Zigbee end devices.
        Returns a list of dictionaries with device info.
        """
        nd_frame = bytes([0x7E, 0x00, 0x04, 0x08, 0x01, 0x4E, 0x44, 0x64])
        self.serialport.reset_input_buffer()
        self.serialport.reset_output_buffer()
        self.serialport.write(nd_frame)
        self.serialport.flush()
        print("[DEBUG] ND frame sent")
        #time.sleep(2)

        devices = []
        start_time = time.time()
        while time.time() - start_time < 5:
            frame = self.read_api_frame()
            if frame:
                parsed = self.parse_xbee_frame(frame)
                if parsed:
                    devices.append(parsed)
                print (f"[DEBUG] nodes : {parsed}")
            else:
                print ("[DEBUG]no zigbee nodes")
                time.sleep(0.05)  # Prevent CPU spin
        return devices

    def read_api_frame(self):
        # Wait for start delimiter
        while True:
            start = self._read_byte(1)
            if start == b'\x7E':
                break
            elif not start:
                return None  # Timeout or no data

        # Read length (2 bytes)
        len_bytes = self._read_byte(2)
        if len(len_bytes) < 2:
            print("[DEBUG] Incomplete length field")
            return None

        length = int.from_bytes(len_bytes, 'big')
        #print (f"[DEBUG]zigbee nodes : {length}")

        # Read the full frame data
        frame_data = self._read_byte(length)
        if len(frame_data) < length:
            print("[DEBUG] Incomplete frame data")
            return None

        # Read checksum
        checksum = self._read_byte(1)
        if not checksum:
            print("[DEBUG] Missing checksum")
            return None

        # Verify checksum
        if (sum(frame_data) + checksum[0]) & 0xFF != 0xFF:
            print("[DEBUG] Checksum error")
            return None

        full_frame = b'\x7E' + len_bytes + frame_data + checksum
        return full_frame


    def parse_xbee_frame(self, raw_bytes):
        if not raw_bytes or raw_bytes[0] != 0x7E:
            print("[DEBUG] Invalid or empty Zigbee frame")
            return None

        if len(raw_bytes) < 5:
            print("[DEBUG] Frame too short to process")
            return None

        length = (raw_bytes[1] << 8) | raw_bytes[2]
        frame_type = raw_bytes[3]
        print(f"[DEBUG] Frame Length: {length}, Frame Type: 0x{frame_type:02X}")
        '''
        if(length < 18):
            return
        '''
    

        if frame_type == 0x95:  # Node Identification
            print("[DEBUG] Node Identification Indicator (0x95) received")
            addr64 = ':'.join(f"{b:02X}" for b in raw_bytes[4:12])
            addr16 = '{:02X}{:02X}'.format(raw_bytes[12], raw_bytes[13])
            ni_start = 14
            ni_end = raw_bytes.find(0x00, ni_start)
            if ni_end == -1:
                ni_end = len(raw_bytes)
            ni = raw_bytes[ni_start:ni_end].decode('utf-8', errors='ignore')
            print(f"[DEBUG] Found device: {ni} at {addr64} (16-bit: {addr16})")
            return {"type": "NI", "addr64": addr64, "addr16": addr16, "ni": ni}
        
        

        elif frame_type == 0x88:
            if(length < 18):
                return
            cmd = raw_bytes[5:7].decode('ascii', errors='ignore')
            if cmd == 'ND' and raw_bytes[7] == 0x00:
                # ND response with node info
                addr64 = ':'.join(f"{b:02X}" for b in raw_bytes[10:18])
                addr16 = ':'.join(f"{b:02X}" for b in raw_bytes[18:20])
                print(f"[DEBUG] ND Response — 64-bit: {addr64}, 16-bit: {addr16}")
                return {"type": "ND", "addr64": addr64, "addr16": addr16}
            else:
                print(f"[DEBUG] AT Command Response: {cmd}")

        elif frame_type == 0x81:
            addr16 = f"{raw_bytes[4]:02X}{raw_bytes[5]:02X}"
            rssi = -raw_bytes[6]  # RSSI is usually negative dBm
            options = raw_bytes[7]

            try:
                # Extract RF data (from byte 8 onwards)
                rf_data = raw_bytes[8:]
                payload_ascii = rf_data.decode('ascii', errors='ignore').strip()

                print(f"[DEBUG] RX Packet — 16-bit: {addr16}, RSSI: {rssi} dBm, Data: {payload_ascii}")

                return {
                    "type": "RX",
                    "addr16": addr16,
                    "rssi": rssi,
                    "options": options,
                    "data": payload_ascii
                }

            except Exception as e:
                print(f"[ERROR] Failed to parse 0x81 payload: {e}")


        elif frame_type == 0x90:  # RF Data Packet
            print("[DEBUG] Receive Packet (0x90) received")
            addr64 = ':'.join(f"{b:02X}" for b in raw_bytes[4:12])
            data = raw_bytes[15:15 + (length - 11)].decode('utf-8', errors='ignore')
            print(f"[DEBUG] Data from {addr64}: {data.strip()}")
            return {"type": "RX", "from": addr64, "data": data}

        else:
            print(f"[DEBUG] Unknown frame type: 0x{frame_type:02X}")
            return None

if __name__ == "__main__":
    ports = Comport.find_all_ports()
    for port in ports:
        c = Comport(port)
        c.open()
        print(f"[INFO] Discovering devices on port {port}...")
        nodes = c.discover_xbee_nodes()
        for node in nodes:
            print(f"  → Node ID: {node['ni']} | 64-bit Addr: {node['addr64']} | 16-bit Addr: {node['addr16']}")
        c.close()
