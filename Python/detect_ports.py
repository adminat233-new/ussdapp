"""Auto-detect USB COM ports (modems / serial devices) on Windows."""
import sys
import serial.tools.list_ports


def detect_ports():
    results = []
    for p in serial.tools.list_ports.comports():
        desc = p.description or ""
        hwid = p.hwid or ""
        is_modem = any(k in desc.lower() for k in ("modem", "zte", "huawei", "sierra", "quectel", "mobile", "cdc", "acm"))
        is_usb = "USB" in hwid.upper() or "USB" in desc.upper()
        results.append({
            "device": p.device,
            "description": desc,
            "hwid": hwid,
            "manufacturer": p.manufacturer or "",
            "is_modem": is_modem,
            "is_usb": is_usb,
        })
    return results


def print_ports():
    ports = detect_ports()
    if not ports:
        print("No COM ports found.")
        return
    print(f"Found {len(ports)} COM port(s):\n")
    for p in ports:
        tags = []
        if p["is_modem"]:
            tags.append("MODEM")
        if p["is_usb"]:
            tags.append("USB")
        tag_str = f" [{', '.join(tags)}]" if tags else ""
        print(f"  {p['device']}: {p['description']}{tag_str}")
        print(f"      HWID: {p['hwid']}  |  Manufacturer: {p['manufacturer']}")
    print()


if __name__ == "__main__":
    print_ports()
