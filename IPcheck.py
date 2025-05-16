import requests

def check_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    api_key = "API of abuseipdb"
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        score = data["data"]["abuseConfidenceScore"]
        if score > 50:
            return "malicious"
        else:
            return "safe"
    except:
        return "unknown"

def check_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        positives = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        if positives > 0:
            return "malicious"
        else:
            return "safe"
    except:
        return "unknown"
    
def check_alienvault(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        pulses = len(data.get("pulse_info", {}).get("pulses", []))
        if pulses > 0:
            return "malicious"
        else:
            return "safe"
    except:
        return "unknown"
    
def check_ip_reputation(ip, api_key):
    """Return 'malicious', 'safe', or 'unknown' based on multiple sources."""
    results = [
        check_abuseipdb(ip),
        check_virustotal(ip, api_key),
        check_alienvault(ip)
    ]
    malicious_count = results.count("malicious")
    safe_count = results.count("safe")
    if malicious_count >= 2:
        print(ip,':malcious')
        return "malicious"
    elif safe_count >= 2:
        print(ip,':safe')
        return "safe"
    else:
        print(ip,':unknown')
        return "unknown"
    
    
    
# Example usage:
#print (check_ip_reputation("218.92.0.228"))