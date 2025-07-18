# Wiredigg: Advanced Network Traffic Analyzer & Threat Detection Tool

[![Platform](https://img.shields.io/badge/platform-Windows-blue)](https://github.com/yourusername/wiredigg)
[![Python](https://img.shields.io/badge/python-3.7%2B-brightgreen)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Wiredigg is an open-source Python tool for real-time network packet capture, deep protocol analysis, anomaly and threat detection (with integrated machine learning), and rich security dashboards. Designed for network administrators, security professionals, and IT enthusiasts, Wiredigg offers a modern user interface, IoT/cloud analytics, and actionable threat intelligence.

**Features include:**
- Real-time packet sniffing and filtering
- Protocol breakdown and statistics
- Machine learning-based anomaly detection (incremental training)
- Integrated threat intelligence (IP/domain/patterns)
- IoT and cloud service analytics
- Export/import, reporting, and more

![Wiredigg Main Interface](Screenshot.png)

## Requirements

- Python 3.7+
- Required Python packages:
  - tkinter
  - numpy
  - matplotlib
  - networkx
  - scikit-learn
  - netifaces
  - pandas

## Installation

1. Clone the repository:
     git clone https://github.com/Zrufy/wiredigg.git
   cd wiredigg
   
2. Install required packages:
     pip install -r requirements.txt
   
3. Run the application:
     python wiredigg.py
   
Note: Administrator/root privileges are required for packet capture on most systems.

## Usage Guide

### Capturing Network Traffic

1. Select a network interface from the dropdown list
2. Click "Start Capture" to begin monitoring network traffic
3. Use filters to focus on specific protocols, IPs, or ports
4. Click "Stop Capture" when done

### Analyzing Threats

1. Navigate to the "Security Analysis" tab
2. Click "Analyze Threats" to scan captured packets for potential security issues
3. Double-click on a detected threat for detailed information
4. View threat details, payload analysis, and security recommendations

### Using Machine Learning Detection

1. Click "ML Detection" to analyze traffic with the machine learning model
2. Mark false positives to improve the model's accuracy
3. Use batch actions to process multiple detections at once

### Working with IoT Devices

1. Navigate to the "IoT/Cloud" tab
2. Click "Identify IoT devices" to detect and classify network devices
3. View detailed information about each device and assess potential risks

### Generating Traffic Predictions

1. Navigate to the "Predictive Analysis" tab
2. Click "Generate Predictions" to view traffic forecasts
3. Monitor potential traffic anomalies and trends

## Advanced Features

### Custom Packet Sending

Use the "Send Simple Packet" feature to test network connectivity and response:

1. Enter destination IP, protocol (TCP/UDP), port, and data
2. Click "Send" to transmit the packet
3. View response data if available

### ML Model Training

The machine learning model improves through incremental training:

1. The model automatically learns from captured traffic
2. Mark false positives to refine detection accuracy
3. Reset the model if necessary using "Reset ML Model"

## Architecture

Wiredigg is built on a multi-threaded architecture to ensure responsive UI while handling intensive packet capture and analysis:

- Main Thread: UI management and user interaction
- Capture Thread: Packet sniffing and initial processing
- Analysis Threads: Security analysis and ML detection
- Background Training: Continuous improvement of the ML model

## Security Database

The application includes an extensible threat database with:

- Known malicious IP addresses
- Attack signatures and patterns
- Vulnerable port information
- File type detection
- Protocol analysis rules

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License**

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- [Tkinter](https://docs.python.org/3/library/tkinter.html) for the UI framework
- [Matplotlib](https://matplotlib.org/) for data visualization
- [NetworkX](https://networkx.org/) for network graph analysis
- [Scikit-learn](https://scikit-learn.org/) for machine learning capabilities
- [Netifaces](https://pypi.org/project/netifaces/) for network interface detection

---

Note: Wiredigg is designed for legitimate network analysis and security purposes only. Always ensure you have proper authorization before capturing network traffic in any environment.
