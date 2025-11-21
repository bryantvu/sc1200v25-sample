from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel,
    QGridLayout, QScrollArea, QHBoxLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from Modified_Comport_discovery import Comport
from Ethernetport_discovery import find_xbee_and_waveshare_devices
import time
from PyQt5.QtGui import QPixmap



class SensorThread(QThread):
    sensor_found = pyqtSignal(str, str, object)

    def __init__(self, ip_list=None, port_list=None):
        super().__init__()
        self.ip_list = ip_list
        self.port_list = port_list

    def run(self):
        ethernet_ports = find_xbee_and_waveshare_devices(self.ip_list, self.port_list)
        #ethernet_ports = find_xbee_and_waveshare_devices()
        ports = Comport.find_all_ports(replace=True)
        ports.extend(ethernet_ports)

        for port in ports:
            try:
                sensor = Comport(port)
                sensor.open()
                # Step 1: Try as normal serial
                sensor.is_zigbee = False
                cid_resp = sensor.get_cid()
                parsed, _ = MainWindow.parse_serial_message_as_dict(cid_resp)

                if parsed and 'CID' in parsed:
                    cid = parsed['CID']
                    self.sensor_found.emit(port, cid, sensor)
                    continue  # success, skip Zigbee check
                else:
                    print(f"[DEBUG] Invalid CID response: {cid_resp}")
                # Check if Zigbee
                nodes = sensor.discover_xbee_nodes()
                if nodes:
                    sensor.is_zigbee = True
                    print(f"[DEBUG] {port} is Zigbee Coordinator with {len(nodes)} nodes")

                    for node in nodes:
                        node_sensor = Comport(port)
                        node_sensor.serialport = sensor.serialport  # Share open port
                        node_sensor.is_zigbee = True
                        node_sensor.addr64 = node['addr64']
                        node_sensor.addr16 = node['addr16']

                        cid_resp = node_sensor.get_cid()
                        parsed, _ = MainWindow.parse_serial_message_as_dict(cid_resp)
                        if parsed and 'CID' in parsed:
                            cid = parsed['CID']
                            label = f"{port}@{node_sensor.addr64}"
                            self.sensor_found.emit(label, cid, node_sensor)
                        time.sleep(0.05)
                    #continue  # Done with this sensor — skip fallback
                '''
                # Not Zigbee — treat as normal serial/ethernet
                sensor.is_zigbee = False
                cid_resp = sensor.get_cid()
                parsed, _ = MainWindow.parse_serial_message_as_dict(cid_resp)
                if parsed and 'CID' in parsed:
                    cid = parsed['CID']
                    self.sensor_found.emit(port, cid, sensor)
                else:
                    print(f"[DEBUG] Invalid CID response: {cid_resp}")
                '''
            except Exception as e:
                print(f"[ERROR] {port}: {e}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SC1200 Sensor Monitor (PyQt5)")
        self.resize(1000, 700)

        self.central = QWidget()
        self.setCentralWidget(self.central)
        self.layout = QVBoxLayout()
        self.central.setLayout(self.layout)

        header_layout = QHBoxLayout()
        title = QLabel("<h1>SC1200 Sensor Monitor</h1>")
        title.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        title.setStyleSheet("font-weight: bold; color: #003366")
        header_layout.addWidget(title, alignment=Qt.AlignLeft)

        try:
            from PyQt5.QtGui import QPixmap
            logo = QLabel()
            pixmap = QPixmap("D:\python\serial_port\LoadVUE-Twelve-Channel\static\logo.png")  # adjust path if needed
            if not pixmap.isNull():
                logo.setPixmap(pixmap.scaledToHeight(60))
                header_layout.addWidget(logo, alignment=Qt.AlignRight)
            else:
                print("Logo file not found or is null")
        except Exception as e:
            print("Logo not loaded:", e)

        self.layout.addLayout(header_layout)
        self.central.setLayout(self.layout)
        #self.cnm_label = QLabel("CID:")
        #self.layout.addWidget(self.cnm_label)

        self.command_bar = QHBoxLayout()
        for cmd in ["SINF", "SNM", "Unit", "Type", "SLC", "WGHT", "WLB", "Raw", "Tare"]:
            btn = QPushButton(cmd)
            btn.clicked.connect(lambda _, c=cmd: self.send_command(c))
            self.command_bar.addWidget(btn)
        self.layout.addLayout(self.command_bar)

        from PyQt5.QtWidgets import QLineEdit

        # IP & Port Input
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IPs comma-separated (e.g., 192.168.1.10,192.168.1.11)")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter Ports comma-separated (e.g., 5000,5001,9750)")

        self.layout.addWidget(self.ip_input)
        self.layout.addWidget(self.port_input)


        self.start_btn = QPushButton("Start")
        self.start_btn.setStyleSheet("background-color: green; color: white; font-weight: bold;")
       # self.start_btn.clicked.connect(self.start_discovery)
        self.start_btn.clicked.connect(self.toggle_connection)
        self.layout.addWidget(self.start_btn)

        self.scroll_area = QScrollArea()
        self.scroll_widget = QWidget()
        self.scroll_layout = QGridLayout()
        self.scroll_widget.setLayout(self.scroll_layout)
        self.scroll_area.setWidget(self.scroll_widget)
        self.scroll_area.setWidgetResizable(True)
        self.layout.addWidget(self.scroll_area)

        self.next_row = 0
        self.sensor_threads = []
        self.sensor_cells = {}  # (port, ch) -> [QLabel, QLabel, ...]
        self.sensor_objects = {}  # port -> Comport instance
        self.connected_ports = []
        self.active_channels = {}  # port -> [ch1, ch2, ...]
    
    
    def toggle_connection(self):
        if self.start_btn.text() == "Start":
            ip_text = self.ip_input.text()
            port_text = self.port_input.text()

            ip_list = [ip.strip() for ip in ip_text.split(',') if ip.strip()] if ip_text else None
            port_list = [int(p.strip()) for p in port_text.split(',') if p.strip().isdigit()] if port_text else None

            print(f"ip_list:{ip_list}")

            thread = SensorThread(ip_list, port_list)
            thread.sensor_found.connect(self.add_sensor_block)
            thread.start()
            self.sensor_threads.append(thread)

            self.start_btn.setText("Stop")
            self.start_btn.setStyleSheet("background-color: red; color: white; font-weight: bold;")
        else:
            self.disconnect_all()
            self.start_btn.setText("Start")
            self.start_btn.setStyleSheet("background-color: green; color: white; font-weight: bold;")


    '''
    def start_discovery(self):
        ip_text = self.ip_input.text()
        port_text = self.port_input.text()

        ip_list = [ip.strip() for ip in ip_text.split(',') if ip.strip()] if ip_text else None
        port_list = [int(p.strip()) for p in port_text.split(',') if p.strip().isdigit()] if port_text else None

        thread = SensorThread(ip_list, port_list)
        thread.sensor_found.connect(self.add_sensor_block)
        thread.start()
        self.sensor_threads.append(thread)
        self.start_btn.setEnabled(False)

    
    def start_discovery(self):
        thread = SensorThread()
        thread.sensor_found.connect(self.add_sensor_block)
        thread.start()
        self.sensor_threads.append(thread)
        self.start_btn.setEnabled(False)
    '''

    def add_sensor_block(self, port, cid, comport_obj):
        active_channels = []
        row_start = self.next_row
        try:
            get_snm = getattr(comport_obj, "get_snm", None)
        except AttributeError:
            get_snm = None

        if get_snm:
            for ch in range(1, 13):
                try:
                    resp = get_snm(ch)          # send "SNM P<ch> "
                    parsed, extras = self.parse_serial_message_as_dict(resp)
                    if parsed and parsed.get("SID"):
                        active_channels.append(ch)
                except Exception as e:
                    print(f"[{port} P{ch}] SNM error: {e}")
        '''
        else:
            # Fallback: if get_snm() doesn't exist, keep old behavior (all 12)
            active_channels = list(range(1, 2))
        '''
        if not active_channels:
            print(f"[INFO] {port}: no channels with ST == 1, skipping rows.")
            # You can return here OR still show headers with no channels if you prefer
            cid_label = QLabel(f"CID: {cid}")
            cid_label.setStyleSheet("background-color: #eee")
            self.scroll_layout.addWidget(cid_label, row_start + 1, 0, 1, 10)
            
            nosensor_label = QLabel("NO SENSORS ATTACHED")
            nosensor_label.setStyleSheet("background-color: #eee")
            self.scroll_layout.addWidget(nosensor_label, row_start + 1, 4, 1, 10)
            self.next_row = row_start + 2 + len(active_channels)
            return

        # Remember for later commands
        self.active_channels[port] = active_channels
        self.connected_ports.append(port)
        self.connected_ports.append(port)

        #row_start = self.next_row
        if getattr(comport_obj, 'addr64',None):
            port_label = QLabel(f"Zigbee Device @ {port} → {comport_obj.addr64}")
        else:
            port_label = QLabel(f"Serial Port: {port}")
        port_label.setStyleSheet("font-weight: bold; background-color: #ddd")
        self.scroll_layout.addWidget(port_label, row_start, 0, 1, 10)
        '''
        if hasattr(comport_obj, 'ni'):
            cid_label = QLabel(f"Node ID: {comport_obj.ni}")
        else:
        '''
        cid_label = QLabel(f"CID: {cid}")
        cid_label.setStyleSheet("background-color: #eee")
        self.scroll_layout.addWidget(cid_label, row_start + 1, 0, 1, 10)

        headings = ["SINF", "SNM", "Status", "Unit", "Type", "LC", "Weight", "WeightLB", "RAW", "Tare"]
        for col, heading in enumerate(headings):
            label = QLabel(heading)
            label.setStyleSheet("font-weight: bold; background-color: lightblue")
            label.setAlignment(Qt.AlignCenter)
            self.scroll_layout.addWidget(label, row_start + 2, col)

        self.sensor_objects[port] = comport_obj
        '''
        for ch in range(1, 13):
            port_label = QLabel(f"P{ch}")
            port_label.setAlignment(Qt.AlignCenter)
            self.scroll_layout.addWidget(port_label, row_start + 2 + ch, 0)
            row_cells = []
            for col in range(1, 10):
                cell = QLabel(" ")
                cell.setStyleSheet("background-color: white; border: 1px solid #ccc")
                self.scroll_layout.addWidget(cell, row_start + 2 + ch, col)
                row_cells.append(cell)
            self.sensor_cells[(port, ch)] = row_cells

        self.next_row += 15
        '''
        for idx, ch in enumerate(active_channels):
            row_index = row_start + 3 + idx

            port_label = QLabel(f"P{ch}")
            port_label.setAlignment(Qt.AlignCenter)
            self.scroll_layout.addWidget(port_label, row_index, 0)

            row_cells = []
            for col in range(1, 10):
                cell = QLabel(" ")
                cell.setStyleSheet("background-color: white; border: 1px solid #ccc")
                self.scroll_layout.addWidget(cell, row_index, col)
                row_cells.append(cell)
            self.sensor_cells[(port, ch)] = row_cells

        # Next block starts after all active rows
        self.next_row = row_start + 3 + len(active_channels)

    def send_command(self, command):
        print(f"[COMMAND] {command} triggered")
        for port, sensor in self.sensor_objects.items():
            # Only channels marked ST == '1' during SNM scan
            channels = self.active_channels.get(port, range(1, 13))

            for ch in channels:
                try:
                    func = getattr(sensor, f"get_{command.lower()}", None)
                    if not func:
                        continue
                    response = func(ch)
                    parsed, extras = self.parse_serial_message_as_dict(response)
                    if parsed and 'P' in parsed:
                        self.update_sensor_row(port, int(parsed['P']), parsed, extras)
                except Exception as e:
                    print(f"[{port} P{ch}] {command} error: {e}")
                time.sleep(1)

    def update_sensor_row(self, port, ch, data, extras):
        row_cells = self.sensor_cells.get((port, ch))
        if not row_cells:
            return
        keys = ['SID', 'ST', 'U', 'TYPE', 'LC', 'W', 'WLB', 'R']
        # Force ST = '1' if SID is present
        
        if 'SID' in data:
            data['ST'] = '1'
        
        for i, key in enumerate(keys):
            row_cells[i].setText(data.get(key, ""))
        # Tare column (last index)
        if extras:
            
            row_cells[-1].setText(", ".join(extras))
        else:
            row_cells[-1].setText("")
        

    @staticmethod
    def xor_checksum(data: str) -> int:
        chk = 0
        for c in data:
            chk ^= ord(c)
        return chk

    @staticmethod
    def parse_serial_message_as_dict(line: str):
        parsed = {}
        extras = []
        line = line.strip()

        if line.startswith('X02'):
            line = line[3:]
        if line.endswith('X03'):
            line = line[:-3]

        segments = line.split('*')
        if len(segments) < 2:
            return None, None

        data_parts = []
        i = 0
        while i < len(segments) - 1:
            data = segments[i]
            chk = segments[i + 1][:2]
            remaining = segments[i + 1][3:] if len(segments[i + 1]) > 2 else ''
            try:
                received_chk = int(chk, 16)
                computed_chk = MainWindow.xor_checksum(data)
                if computed_chk != received_chk:
                    return None, None
                data_parts.append(data)
                segments[i + 1] = remaining
                i += 1
            except ValueError:
                return None, None

        if segments[-1]:
            data_parts.append(segments[-1])

        full_data = ','.join(data_parts).replace(',,', ',')
        
        for kv in full_data.split(','):
            if ':' in kv:
                try:
                    key, value = kv.split(':', 1)
                    parsed[key.strip()] = value.strip()
                except ValueError:
                    continue
            else:
                extras.append(kv.strip())
        # Filter extras
        ALLOWED_FLAGS = {"Tared", "Calibrated", "OK"}
        extras = [e for e in extras if e in ALLOWED_FLAGS]

        return parsed, extras
    '''
    def toggle_connection(self):
        if self.start_btn.text() == "Start":
            thread = SensorThread()
            thread.sensor_found.connect(self.add_sensor_block)
            thread.start()
            self.sensor_threads.append(thread)
            self.start_btn.setText("Stop")
            self.start_btn.setStyleSheet("background-color: red; color: white; font-weight: bold;")
        else:
            self.disconnect_all()
            self.start_btn.setText("Start")
            self.start_btn.setStyleSheet("background-color: green; color: white; font-weight: bold;")
    '''
    def disconnect_all(self):
        for port in self.connected_ports:
            try:
                if port in self.sensor_objects:
                    self.sensor_objects[port].close()
            except Exception as e:
                print(f"Error closing {port}: {e}")
        self.connected_ports.clear()
        self.sensor_objects.clear()
        self.sensor_cells.clear()
        self.scroll_layout = QGridLayout()
        self.scroll_widget.setLayout(self.scroll_layout)
        self.next_row = 0



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
