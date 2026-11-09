"""Method 2: USB serial / AT-command USSD over a COM port."""
import time
import serial
from serial.tools import list_ports
from detect_ports import detect_ports


def auto_detect_modem_port():
    """Return best-guess modem COM port, preferring modem-labeled USB devices."""
    ports = detect_ports()
    modem_ports = [p for p in ports if p["is_modem"]]
    usb_ports = [p for p in ports if p["is_usb"]]
    if modem_ports:
        return modem_ports[0]["device"]
    if usb_ports:
        return usb_ports[0]["device"]
    if ports:
        return ports[0]["device"]
    return None


def _read_until_idle(ser, timeout=12.0, idle=1.0):
    """Read serial data until timeout or idle gap. USSD replies end with OK or timeout."""
    ser.timeout = 0.3
    deadline = time.time() + timeout
    buf = []
    last_data = time.time()
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            buf.append(chunk.decode("utf-8", errors="replace"))
            last_data = time.time()
        elif buf and (time.time() - last_data) > idle:
            break
    return "".join(buf)


def send_ussd_at(port, ussd_code, baud=115200, timeout=15.0):
    """Open COM port, send AT+CUSD, collect the network response text."""
    with serial.Serial(port=port, baudrate=baud, timeout=1, write_timeout=3) as ser:
        time.sleep(0.4)
        ser.reset_input_buffer()
        ser.write(b"AT\r")
        _read_until_idle(ser, timeout=3, idle=0.4)
        ser.reset_input_buffer()
        cmd = f'AT+CUSD=1,"{ussd_code}",15\r'
        ser.write(cmd.encode())
        reply = _read_until_idle(ser, timeout=timeout, idle=1.2)
        return reply


def extract_ussd_text(reply):
    """Parse +CUSD: response body from raw AT reply."""
    for line in reply.splitlines():
        line = line.strip()
        if "+CUSD:" in line:
            parts = line.split(",", 1)
            if len(parts) > 1:
                text = parts[1].strip().strip('"')
                text = text.rstrip(",15").rstrip(",1").rstrip(",0")
                return text
    return reply.strip()


if __name__ == "__main__":
    import sys
    argv = sys.argv[1:]
    if len(argv) >= 2:
        port, code = argv[0], argv[1]
        baud = int(argv[2]) if len(argv) > 2 else 115200
    else:
        port = auto_detect_modem_port()
        code = input("USSD code (default *124#): ").strip() or "*124#"
        baud = 115200
    print(f"Port: {port}  Code: {code}  Baud: {baud}")
    if not port:
        print("No COM port found. Plug in the MiFi via USB and retry.")
        raise SystemExit(1)
    try:
        raw = send_ussd_at(port, code, baud=baud)
        print("Raw reply:\n", raw)
        print("Parsed text:", extract_ussd_text(raw))
    except Exception as ex:
        print(f"Error: {ex}")
        raise SystemExit(1)
