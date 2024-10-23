"""
SOHAN's Enhanced Phishing URL Detector - Log Viewer
Credit for this project goes to SOHAN.
Enhanced with VirusTotal API integration.
"""

def view_logs():
    print("SOHAN's Enhanced Phishing URL Detector - Log Viewer")
    print("Credit for this project goes to SOHAN.")
    print("Enhanced with VirusTotal API integration.")
    print()
    try:
        with open("url_log.txt", "r") as log_file:
            logs = log_file.readlines()

        if not logs:
            print("No logs found.")
            return

        print("URL Check Logs:")
        print("-" * 120)
        print(f"{'Timestamp':<20} | {'Status':<10} | {'URL':<50} | {'Reason'}")
        print("-" * 120)

        for log in logs:
            parts = log.strip().split(" | ", 3)
            if len(parts) == 4:
                timestamp, status, url, reason = parts
                print(f"{timestamp:<20} | {status:<10} | {url:<50} | {reason}")
            else:
                print(f"Invalid log entry: {log.strip()}")

    except FileNotFoundError:
        print("Log file not found. Run the phishing detector first to create logs.")

if __name__ == "__main__":
    view_logs()