import re
import csv
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_count = defaultdict(int)
    for log in logs:
        ip_address = log.split()[0]
        ip_count[ip_address] += 1
    return ip_count

def identify_most_accessed_endpoint(logs):
    endpoint_count = defaultdict(int)
    for log in logs:
        match = re.search(r'"(GET|POST) (.+?) HTTP/', log)
        if match:
            endpoint = match.group(2)
            endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1], default=(None, 0))
    return most_accessed

def detect_suspicious_activity(logs):
    failed_logins = defaultdict(int)
    for log in logs:
        if '401' in log or 'Invalid credentials' in log:
            ip_address = log.split()[0]
            failed_logins[ip_address] += 1
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_results_to_csv(ip_counts, most_accessed, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_file_path = 'sample.log' 
    logs = parse_log_file(log_file_path)

    ip_counts = count_requests_per_ip(logs)
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    most_accessed = identify_most_accessed_endpoint(logs)
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    suspicious_ips = detect_suspicious_activity(logs)
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    save_results_to_csv(ip_counts, most_accessed, suspicious_ips)

if __name__ == "__main__":
    main()