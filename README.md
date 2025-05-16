# ForenSieght - Advanced Cybersecurity Analyzer

ForenSight is a comprehensive, multi-threaded cybersecurity analysis tool designed to provide deep insights into system activity, identify potential security threats, and streamline incident response. It integrates data collection, Gemini APIs, and real-time analysis to detect and classify suspicious behaviors across various system components.

## 🚀 Key Features

* **Real-Time Threat Detection** - Detects high-entropy commands, random names, unusual parent-child relationships, and potentially malicious file hashes.
* **IP and File Reputation Analysis** - Integrates with VirusTotal, AbuseIPDB, and AlienVault for comprehensive IP and file reputation checks.
* **Firewall and Startup Monitoring** - Flags suspicious startup entries and firewall modifications using Gemini API.
* **DLL, SMB, and File Integrity Checks** - Identifies non-standard DLL paths, raw disk partitions, and potentially risky file changes.
* **Automated Multi-Threaded Analysis** - Optimized for high-speed data processing using ThreadPoolExecutor.
* **Interactive GUI** - Intuitive, feature-rich graphical interface for real-time analysis and data visualization.

## 📦 Installation

### Prerequisites

Ensure you have the following installed:

* Python 3.8+
* Required libraries (install with the command below)

### Setup

```bash
# Clone the repository
git clone https://github.com/Mohamed-Elshahally/ForenSight.git
cd ForenSight

# Install required libraries
pip install -r requirements.txt
```

## 📝 Configuration

### API Keys

Ensure you have the required API keys set up:

* **VirusTotal** - for file and IP reputation checks
* **Gemini API** - for startup and firewall event analysis

Add your keys to `AnalyzeData.py` and `IPcheck.py` as follows:

```python
API_KEYS = ["<YOUR_VIRUSTOTAL_API_KEYS>"]
Gemini_Key = ["<YOUR_GEMINI_API_KEYS>"]
api_key= ["<YOUR_abuseipdb_API_KEY>"] # check_abuseipdb from IPcheck.py 
```

### Directory Structure

Ensure your data is structured as follows:

```
ForenSight/
├── AnalyzeData.py
├── CollectData.ps1
├── filehashcheck.py
├── gemini.py
├── geminiapp.py
├── geminifw.py
├── geministartup.py
├── geminisys.py
├── GUI.py
├── IPcheck.py
└── requirements.txt
```

## 🚀 Usage

Run the main GUI application with:

```bash
python GUI.py
```

## 📋 Modules Overview

### Key Scripts

* **AnalyzeData.py** - Core analysis engine, handling processes, ports, and file hashes.
* **filehashcheck.py** - VirusTotal hash checks.
* **gemini.py, geminiapp.py, geminifw\.py, geministartup.py, geminisys.py** - Gemini API integrations for various log types.
* **IPcheck.py** - Multi-source IP reputation checks.
* **GUI.py** - Interactive interface for managing analysis.

### PowerShell Data Collection

Use the included `CollectData.ps1` script to gather essential Windows system data:

```powershell
powershell -ExecutionPolicy Bypass -File CollectData.ps1
```

## 🔒 Security Considerations

* **Protect Your API Keys** - Never commit your API keys to public repositories.
* **Data Privacy** - Ensure data collection complies with your organization's privacy policies.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙌 Contributing

Feel free to open issues or pull requests to contribute to this project.

## 🗂️ Future Enhancements

* Machine Learning-based threat detection
* Real-time alerting and automated response
* Dark web monitoring integration
* Enhanced file and network anomaly detection

## 💬 Support

For any questions or support, feel free to reach out or open an issue in this repository.

---

Thanks for using ForenSight! Happy Hunting!
