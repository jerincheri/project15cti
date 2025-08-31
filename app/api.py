import requests
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

def lookup_threat(query):
    result = {
        "query": query,
        "tags": [],
        "threat_level": "Unknown",
        "sources": [],
    }

    # VirusTotal Lookup
    vt_url = f"https://www.virustotal.com/api/v3/domains/{query}" if "." in query else f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
    vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    vt_response = requests.get(vt_url, headers=vt_headers)

    if vt_response.status_code == 200:
        vt_data = vt_response.json()
        result["sources"].append("VirusTotal")
        result["tags"].extend(vt_data.get("data", {}).get("attributes", {}).get("tags", []))
        result["threat_level"] = "Malicious" if vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0 else "Clean"

    # AbuseIPDB Lookup (only for IPs)
    if "." in query and query.replace(".", "").isdigit():
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        abuse_headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        abuse_params = {
            "ipAddress": query,
            "maxAgeInDays": 90
        }
        abuse_response = requests.get(abuse_url, headers=abuse_headers, params=abuse_params)

        if abuse_response.status_code == 200:
            abuse_data = abuse_response.json()
            result["sources"].append("AbuseIPDB")
            abuse_score = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)
            if abuse_score > 50:
                result["threat_level"] = "Suspicious"
            result["tags"].append(f"Abuse Score: {abuse_score}")

    return result
