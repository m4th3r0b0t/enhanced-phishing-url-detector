# Enhanced Phishing URL Detector

A Python-based tool to detect potential phishing URLs using basic heuristics, VirusTotal API integration, and logging capabilities. Credit for this project goes to SOHAN.

## Features

- Checks URLs for common phishing indicators
- Integrates with VirusTotal API for enhanced detection
- Logs results with timestamps
- Provides a separate script to view logged results in a user-friendly format
- Uses built-in Python libraries and minimal external dependencies

## Credit

This project was conceived and developed by SOHAN. All credit for the original idea and implementation goes to them. The project has been enhanced with VirusTotal API integration.

## Requirements

- Python 3.6 or higher
- requests
- python-dotenv

## Setup

1. Clone this repository or download the source code:

   ```
   git clone https://github.com/m4th3r0b0t/enhanced-phishing-url-detector.git
   cd enhanced-phishing-url-detector
   ```

2. Install the required packages:

   ```
   pip install requests python-dotenv
   ```

3. Sign up for a VirusTotal API key at https://www.virustotal.com/gui/join-us

4. Create a `.env` file in the project directory and add your VirusTotal API key:

   ```
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ```

## Usage

### Detecting Phishing URLs

Run the main script to start checking URLs:

```
python phishing_detector.py
```

Enter URLs when prompted. The script will analyze each URL using both local checks and the VirusTotal API, then display the result. It will also log the results to a file named `url_log.txt`.

To exit the program, type 'quit' when prompted for a URL.

### Viewing Logged Results

To view the logged results in a formatted table, run:

```
python view_logs.py
```

This will display all logged URL checks in a user-friendly format.

## How It Works

Enhanced Phishing URL Detector uses several methods to identify potential phishing URLs:

1. Presence of common phishing keywords
2. Use of IP addresses instead of domain names
3. Matching against a hardcoded list of blacklisted domains
4. Detection of suspiciously long URLs
5. Identification of potential typosquatting attempts on popular brand names
6. Integration with VirusTotal API for additional threat intelligence

## Limitations

While this implementation provides more robust detection capabilities than the basic version, it may still not catch all phishing attempts. It's meant for educational purposes and as a starting point for more advanced phishing detection systems. For an even more robust solution, consider:

- Implementing machine learning techniques
- Regularly updating the list of phishing indicators and blacklisted domains
- Using additional threat intelligence sources

## Contributing

While this project is primarily credited to SOHAN, contributions to improve the Enhanced Phishing URL Detector are welcome. Please feel free to submit pull requests or open issues to suggest improvements or report bugs. Make sure to credit SOHAN for the original work when contributing.

## License

This project is open-source and available under the MIT License. Please ensure that you provide appropriate credit to SOHAN when using or modifying this project.
