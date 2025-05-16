import requests
import time

def check_virustotal(file_hash, api_key, retries=3):
    """
    Check the file hash against VirusTotal.
    
    :param file_hash: The SHA-256 hash of the file.
    :param api_key: VirusTotal API key.
    :param retries: Number of retry attempts for API calls.
    :return: 'malicious', 'safe', or 'unknown'.
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            detections = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            return "malicious" if detections > 5 else "safe"
        except requests.RequestException as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            print(f"VirusTotal error for {file_hash}: {e}")
            return "unknown"




def scan_hash_and_decide(file_hash, api_key_vt):
    """
    Decide if the file hash is malicious based on VirusTotal.
    
    :param file_hash: The SHA-256 hash of the file.
    :param api_key_vt: VirusTotal API key.
    :return: (True/False, message)
    """
    vt_result = check_virustotal(file_hash, api_key_vt)
    if vt_result == "malicious":
        decision = "malicious"
    elif vt_result == "safe":
        decision = "safe"
    else:
        decision = "unknown"

    report_url = f"https://www.virustotal.com/gui/file/{file_hash}" if vt_result != "unknown" else ""
    print(f"{file_hash}: {decision}")
    return (decision == "malicious", f"Decision: {decision}, Report: {report_url}")
