import requests
import time
import os
import sys

# Variables to set
API_BASE_URL = "https://api.probely.com"
API_TOKEN = os.getenv("PROBELY_API_TOKEN")
TARGET_ID = os.getenv("TARGET_ID")
POLL_INTERVAL = "180"

# Set Headers for API Calls

headers = {
    "Accept": "application/json",
    "Authorization": f"JWT {API_TOKEN}",
}

# Function for starting a scan
def start_scan():
    print (f"Starting scan for target {TARGET_ID}")
    url = f"{API_BASE_URL}/targets/{TARGET_ID}/scan_now/"
    try:
        response = requests.post(url, headers=headers, json={})
        response.raise_for_status()
        data = response.json()
        scan_id = data.get("id")
        if not scan_id:
            print("Failed to start scan. Please validate Target ID/Permissions")
            sys.exit(1)
        print(f"Scan started successfully. Scan ID: {scan_id}")
        return scan_id
    except requests.exceptions.RequestException as e:
        print(f"Error starting scan: {e}")
        sys.exit(1)

# Function for waiting for scan to complete
def wait_for_scan(scan_id):
    start_time = time.time()
    url = f"{API_BASE_URL}/targets/{TARGET_ID}/scans/{scan_id}/"
    while True:
        print("Checking scan status")
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            status = data.get("status")
            if status == "completed":
                print("scan completed succesfully")
                return
            elif status == "failed":
                print("scan failed, see Probely UI for details")
                sys.exit(1)
            print(f"scan status: {status}. Waiting for {POLL_INTERVAL} seconds")
            time.sleep(int(POLL_INTERVAL))
        except requests.exceptions.RequestException as e:
            print(f"Error getting scan status: {e}")
            sys.exit(1)

# Function to fetch findings
def fetch_and_check_findings():
    print("Fetching findings and checking for high sev")
    url = f"{API_BASE_URL}/targets/{TARGET_ID}/findings/"
    high_severity_findings = []
    
    try:
        current_page = 1
        while True:
            response = requests.get(url, headers=headers, params={"pages": current_page})
            response.raise_for_status()
            data = response.json()
            findings = data.get("results", [])
            high_severity_findings.extend([item for item in data.get("results", []) if item.get("severity") == 30])
            page_total = data.get("page_total")
            if current_page >= page_total:
                break
            current_page +=1
        count = len(high_severity_findings)
        if count > 0:
            print(f" {count} high severity findings detected, please see web UI for results")
            sys.exit(1)
        else:
            print("no high severity findings found")
    except requests.exceptions.RequestException as e:
            print(f"Error getting findings: {e}")
            sys.exit(1)

# Start the scan, wait for completion
def main():
    if not API_TOKEN or not TARGET_ID:
        print("Error: API_TOKEN or TARGET)ID is not set.")
        sys.exit(1)
    
    scan_id = start_scan()
    wait_for_scan(scan_id)
    fetch_and_check_findings()

    print ("This has passed")

if __name__ == "__main__":
    main()
