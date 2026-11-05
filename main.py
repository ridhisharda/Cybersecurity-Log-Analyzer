def get_threshold():
    while True:
        threshold = input("Enter the failed login threshold: ")  # Threshold for suspicious activity
        if threshold.isdigit():
            threshold = int(threshold)
            if threshold > 0:
                return threshold
            else:
                print("Please enter a positive integer for the threshold.")
        else:
            print("Invalid input! Please enter a positive integer for the threshold.")
def analyze_logs():
    successful_logins = 0
    failed_logins = 0
    failed_attempts = {}
    failed_timestamps = {}
    try:
        file = open("login_logs.txt", "r")
    except FileNotFoundError:
        print("Error: The file 'login_logs.txt' was not found.")
        return None
    invalid_logs = 0
    for line in file:
        data = line.strip().split(",")
        if line.strip() == "":
            continue  # Skip empty lines
        if len(data) != 3:
            invalid_logs += 1
            print(f"Warning: Invalid log entry skipped: {line.strip()}")
            continue
        timestamp = data[0]
        ip_address = data[1]
        status = data[2]
        if status != "SUCCESS" and status != "FAILED":
            invalid_logs += 1
            print(f"Warning: Invalid status in log entry skipped: {line.strip()}")
            continue
        if status == "SUCCESS":
            successful_logins += 1
        elif status == "FAILED":
            failed_logins += 1
            if ip_address in failed_attempts:
                failed_attempts[ip_address] += 1
            else:
                failed_attempts[ip_address] = 1
            if ip_address not in failed_timestamps:
                failed_timestamps[ip_address] = []
            failed_timestamps[ip_address].append(timestamp)
    file.close()
    return successful_logins, failed_logins, failed_attempts, failed_timestamps, invalid_logs
def display_report(successful_logins, failed_logins, failed_attempts, failed_timestamps, threshold, invalid_logs):
    total_attempts = successful_logins + failed_logins
    print("===== LOGIN ANALYSIS REPORT =====")
    print(f"Total Attempts: {total_attempts}")
    print(f"Successful Logins: {successful_logins}")
    print(f"Failed Logins: {failed_logins}")
    print(f"Invalid Log Entries: {invalid_logs}")
    print("\n===== Failed Attempts by IP Address =====")
    for ip_address, count in failed_attempts.items():
        print(f"{ip_address}: {count}")
    print("\n===== SECURITY ALERTS =====")
    suspicious_found = False
    for ip_address, count in failed_attempts.items():
        if count > threshold:
            suspicious_found = True
            print("WARNING: Suspicious activity detected!")
            print("IP Address:", ip_address)
            print("Failed Attempts:", count)
            print("Failed login times:")
            for time in failed_timestamps[ip_address]:
                print(" -", time)
            print("--------------------------------")
    if not suspicious_found:
        print("No suspicious activity detected.")
def save_report(successful_logins, failed_logins, failed_attempts, failed_timestamps, threshold, invalid_logs):
    total_attempts = successful_logins + failed_logins  
    report = open("security_report.txt", "w")
    report.write("===== CYBERSECURITY LOG ANALYSIS REPORT =====\n")
    report.write(f"Total Attempts: {total_attempts}\n")
    report.write(f"Successful Logins: {successful_logins}\n")
    report.write(f"Failed Logins: {failed_logins}\n")
    report.write(f"Invalid Log Entries: {invalid_logs}\n")
    report.write("\n===== Failed Attempts by IP Address =====\n")
    for ip_address, count in failed_attempts.items():
        report.write(f"{ip_address}: {count}\n")
    report.write("\n===== SECURITY ALERTS =====\n")
    for ip_address, count in failed_attempts.items():
        if count > threshold:
            report.write("WARNING: Suspicious activity detected!\n")
            report.write(f"IP Address: {ip_address}\n")
            report.write(f"Failed Attempts: {count}\n")
            report.write("Failed login times:\n")
            for timestamp in failed_timestamps[ip_address]:
                report.write(f" - {timestamp}\n")
        
    report.close()
    print("\nSecurity report saved successfully.")
threshold = get_threshold()
result = analyze_logs()
if result is not None:
    successful_logins, failed_logins, failed_attempts, failed_timestamps, invalid_logs = result
    display_report(successful_logins, failed_logins, failed_attempts, failed_timestamps, threshold, invalid_logs)
    save_report(successful_logins, failed_logins, failed_attempts, failed_timestamps, threshold, invalid_logs)
