"""Method 1: MiFi hidden backend web API USSD (ZTE goform endpoints)."""
import time
import requests


def send_ussd(mifi_ip, ussd_code, timeout=15):
    mifi_ip = mifi_ip.rstrip("/")
    post_url = f"{mifi_ip}/goform/goform_set_cmd_process"
    payload = {
        "isAsync": "true",
        "goformId": "USSD_PROCESS",
        "USSD_cmd": ussd_code,
        "USSD_action": "1",
    }
    headers = {"Referer": f"{mifi_ip}/index.html"}
    res = requests.post(post_url, data=payload, headers=headers, timeout=timeout)
    return res.text


def get_ussd_result(mifi_ip, timeout=15):
    mifi_ip = mifi_ip.rstrip("/")
    get_url = f"{mifi_ip}/goform/goform_get_cmd_process?cmd=USSD_result&multi_data=1"
    headers = {"Referer": f"{mifi_ip}/index.html"}
    res = requests.get(get_url, headers=headers, timeout=timeout)
    try:
        return res.json()
    except Exception:
        return {"raw": res.text}


def ussd_session(mifi_ip, ussd_code, wait_seconds=3, attempts=5, poll_interval=1.5):
    """Send USSD, poll for result, return (send_status, network_response)."""
    send_status = send_ussd(mifi_ip, ussd_code)
    time.sleep(wait_seconds)
    result = None
    for _ in range(attempts):
        result = get_ussd_result(mifi_ip)
        text = str(result)
        if text and text not in ("{}", "{'ussd_status': 'idle'}", '{"ussd_status": "idle"}'):
            if "ussd" in text.lower() or "content" in text.lower():
                break
        time.sleep(poll_interval)
    return send_status, result


if __name__ == "__main__":
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.100.1"
    code = sys.argv[2] if len(sys.argv) > 2 else "*124#"
    print(f"Target: {ip}  Code: {code}")
    s, r = ussd_session(ip, code)
    print("Send status:", s)
    print("Network response:", r)
