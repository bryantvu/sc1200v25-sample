# SC1200 Multi-Channel Sensor Viewer

This project is a simple Python application that allows you to view and read data from Loadstar **SC1200** sensor devices.  
You can connect SC1200 using:

- Serial (COM)  
- Ethernet (TCP/IP)  
- Zigbee (XBee)

A graphical interface (GUI) is included so you can read sensor values without typing commands.

---

## What This Application Does

- Automatically finds available COM and Ethernet devices  
- Shows up to **12 sensor channels** in one window  
- Lets you send basic commands like:
  - Read weight (WGHT)
  - Read sensor name (SNM)
  - Read device ID (CID)
  - Read sensor info (SINF)
- Displays the values in an easy-to-read table  

---

## Files in This Project

```
Modified_gui_qt5.py          → GUI program
Modified_Comport_discovery.py → Serial & Zigbee communication code
Ethernetport_discovery.py     → Ethernet communication code
ethernet_read.py              → Simple Ethernet test tool
sc1200_demo.py                → Main launcher program for the GUI
```

---

## Requirements

You need:

- Python 3.8 or newer  
- pyserial  
- PyQt5  

Install the required packages:

```
pip install pyserial PyQt5
pip install pyserial pyserial
```

---

## How to Run the GUI

1. Connect your SC1200  
2. Open a terminal  
3. Run the main program

```
python sc1200_demo.py
```

4. The GUI window will open  
5. Enter the **IP address** and **port** of your SC1200  
6. Click **Start** to connect  
7. Once the 12 columns load, you can click any button:
   - **WGHT**
   - **SNM**
   - **SINF**
   - **CID**

   to read data from all channels

---

## Notes

- This application is mainly for testing and viewing SC1200 data  
- The GUI updates all channels at the same time after receiving valid responses  
- Works for both single-channel and multi-channel configurations  

---

## Contact

If you need help setting up your device or improving the GUI, feel free to ask.

