
# Cybersecurity Log Analyzer

A Python-based cybersecurity project that analyzes login logs, identifies suspicious login activity, and generates security reports.

## Features

- Reads login records from a text file.
- Counts successful and failed login attempts.
- Tracks failed attempts by IP address.
- Records timestamps of failed logins.
- Detects suspicious IP addresses using a customizable threshold.
- Validates user input.
- Handles missing log files.
- Detects and skips invalid log entries.
- Generates a security report.

## Technologies Used

- Python 3
- Dictionaries
- Lists
- Loops and conditional statements
- Functions
- File handling
- Exception handling

## How to Run

1. Install Python 3.
2. Download or clone this repository.
3. Open the project folder in VS Code.
4. Run:

   python main.py

5. Enter your desired failed-login threshold.

## Project Files

- `main.py` – Main application.
- `login_logs.txt` – Sample login records.
- `security_report.txt` – Generated analysis report.

## Future Improvements

- Visualize login activity using charts.
- Add a graphical user interface.
- Detect unusual login patterns.
- Support larger log files.
