Advanced Network Automation Tool
A comprehensive GUI-based network automation and monitoring tool built with Python and tkinter. This tool provides network administrators with powerful utilities for network discovery, monitoring, and device management.

👨‍💻 Author
Dr. Mohammed Tawfik

📧 Email: kmkhol01@gmail.com

🔗 GitHub: https://github.com/kmkholm/

🚀 Features
📡 Network Scanner
Multi-threaded network discovery
Real-time host detection with MAC address and vendor lookup
Configurable timeout and thread settings
Export results in CSV, JSON, or TXT formats
🔌 Port Scanner
TCP Connect and TCP SYN scan types
Service detection and banner grabbing
Quick scan presets for common port groups
Open port identification with service names
📊 Ping Monitor
Real-time network monitoring
Statistics tracking (sent, received, lost packets)
Success rate and latency analysis
Export monitoring logs
🔐 SSH Automation
Remote device connection via SSH
Command execution on network devices
Script execution capabilities
Multi-device command execution
💾 Configuration Backup
Automated device configuration backup
Support for multiple devices
Scheduled backup capabilities
Backup in TXT and JSON formats
🌐 SNMP Monitor
SNMP device monitoring
MIB browser with common OIDs
SNMP get, walk, and bulk operations
Device information retrieval
🛠 Network Tools
Traceroute analysis
DNS lookup functionality
Whois information gathering
Bandwidth testing capabilities
📋 Device Inventory
Complete device database management
Import/export device lists
Device search and filtering
Multiple device type support
📦 Installation
Prerequisites
Python 3.7 or higher
tkinter (usually included with Python)
Optional Dependencies
bash
# For SSH automation features
pip install paramiko
Quick Start
1.
Clone the repository:
bash
git clone https://github.com/kmkholm/network-automation-tool.git
cd network-automation-tool
2.
Run the application:
bash
python network_automation_tool.py
🎯 Usage
Network Scanning
1.
Navigate to the Network Scanner tab
2.
Enter IP range (e.g., 192.168.1.0/24)
3.
Configure threads and timeout settings
4.
Click Start Scan to begin discovery
Port Scanning
1.
Go to the Port Scanner tab
2.
Enter target IP or hostname
3.
Specify port range (e.g., 1-1000 or 80,443)
4.
Select scan type and start scanning
SSH Automation
1.
Open SSH Automation tab
2.
Enter device connection details
3.
Click Connect to establish SSH session
4.
Execute commands or run scripts
Device Management
1.
Use Device Inventory tab for device management
2.
Add, edit, or delete devices
3.
Import/export device lists
4.
Search and filter devices
🎨 Interface
The tool features a modern tabbed interface with:

Network Scanner: Host discovery and network mapping
Port Scanner: Service enumeration and security assessment
Ping Monitor: Real-time network monitoring
SSH Automation: Remote device management
Config Backup: Automated configuration backup
SNMP Monitor: Network device monitoring
Network Tools: Diagnostic utilities
Device Inventory: Asset management
Settings: Application configuration
⚙️ Configuration
Application Settings
Default timeout settings
Maximum thread configuration
Theme selection (Dark/Light)
Network default values
Logging configuration
File Locations
Settings: network_tool_settings.json
Logs: network_tool.log
Backups: ./backups/ (configurable)
🔧 Technical Details
Built With
Python 3.7+
tkinter - GUI framework
paramiko - SSH library
threading - Multi-threading support
concurrent.futures - Thread pool management
Architecture
Multi-threaded design for responsive GUI
Background processing for network operations
Modular tab-based interface
Export/import capabilities
📄 License
This project is open source. Please see the LICENSE file for details.

🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

📞 Support
For support, questions, or feature requests:

Email: kmkhol01@gmail.com
GitHub Issues: Create an issue
📝 Changelog
v2.4 Final
Fixed SNMP monitor tab NameError
Single-file architecture
Enhanced error handling
Complete feature implementation
Improved user interface
Made with ❤️ by Dr. Mohammed Tawfik

Empowering network administrators with automation tools
