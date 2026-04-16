# Offensive Security IoT Device Vulnerability Scanner

A professional-grade tool for identifying security weaknesses in Internet of Things (IoT) devices through comprehensive vulnerability assessment, penetration testing, and security research.

## Overview

This tool is designed for:
- **Ethical Hackers** - Learning offensive security concepts
- **Penetration Testers** - Authorized security testing
- **Cybersecurity Researchers** - IoT security analysis
- **Security Teams** - Internal network assessments

### Target IoT Devices
- Smart Cameras & IP Cameras
- WiFi Routers & Network Switches
- Smart Bulbs & Lighting Systems
- Home Automation Devices
- Smart Locks & Access Control
- Network-Attached Storage (NAS)
- Video Doorbells
- Smart TVs & Media Players
- Industrial IoT Devices

## ⚠️ LEGAL & ETHICAL DISCLAIMER

```
THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY

• Unauthorized network scanning is ILLEGAL in most jurisdictions
• Obtain explicit written permission before testing any network
• Violating the Computer Fraud and Abuse Act (CFAA) can result in:
  - Criminal prosecution
  - Federal prison time (up to 10 years)
  - Substantial fines ($250,000+)
  - Civil liability

USE RESPONSIBLY AND ETHICALLY
```

##  Features

### Network Discovery
- Automated IoT device discovery on network ranges
- Hostname resolution and device identification
- Network mapping and visualization

### Port Scanning
- Multi-threaded port scanning for speed
- Service identification (HTTP, HTTPS, SSH, Telnet, FTP, SNMP, etc.)
- Open port enumeration
- Common IoT port database (23, 21, 80, 443, 8080, 161, 5357, etc.)

### Vulnerability Detection
- **Insecure Protocols**: Detects Telnet, FTP, unencrypted HTTP
- **Default Credentials**: Tests against 100+ common default passwords
- **Authentication Issues**: Identifies services without authentication
- **Protocol Vulnerabilities**: SSH version detection, deprecated protocols
- **Firmware Versions**: Outdated firmware identification
- **Weak Encryption**: SSL/TLS configuration issues

### Risk Assessment
- **CRITICAL**: Immediate action required (default creds, Telnet, FTP)
- **HIGH**: Address within 48 hours (unencrypted protocols, old firmware)
- **MEDIUM**: Address within 1-2 weeks (weak configs, info disclosure)

### Reporting
- JSON format for integration with other tools
- Risk breakdown and prioritization
- Remediation guidance for each vulnerability
- Executive summary with key metrics

##  Installation

### Requirements
```bash
pip install requests beautifulsoup4 PyQt5 python-nmap paramiko
```

### Linux
```bash
sudo apt-get install nmap
pip install -r requirements.txt
```

### macOS
```bash
brew install nmap
pip install -r requirements.txt
```

### Windows
- Download Nmap from https://nmap.org/download.html
- Install with GUI
- Then: `pip install -r requirements.txt`

## Usage

### GUI Version (Recommended)
```bash
python3 iot_scanner_gui.py
```

**Steps:**
1. Enter network range (e.g., `192.168.1.0/24`)
2. Specify target device or leave for full scan
3. Click "Start Scan"
4. Review vulnerabilities in tabs
5. Generate report

### Command Line Version
```bash
python3 iot_scanner.py
```

Edit the script to specify:
- Network range: `network_range = "192.168.1.0/24"`
- Target device: `test_ip = "192.168.1.1"`

##  Vulnerability Categories

### 1. Insecure Communication Protocols

| Protocol | Risk | Details |
|----------|------|---------|
| **Telnet (23)** | CRITICAL | Plain text transmission, no encryption |
| **FTP (21)** | CRITICAL | Credentials & data sent unencrypted |
| **HTTP (80)** | HIGH | No encryption, vulnerable to MITM |
| **SSH v1 (22)** | HIGH | Known cryptographic weaknesses |

### 2. Authentication Issues

| Issue | Risk | Remediation |
|-------|------|------------|
| Default Credentials | CRITICAL | Change all default passwords |
| No Authentication | CRITICAL | Enable authentication |
| Weak Credentials | CRITICAL | Enforce strong password policies |
| Account Enumeration | MEDIUM | Limit failed login attempts |

### 3. Outdated Firmware
- Vulnerable to known exploits
- Missing security patches
- Unpatched CVEs

### 4. Service Exposure
- Unnecessary services enabled
- Unneeded ports open
- Exposed admin interfaces

### 5. Information Disclosure
- Server banners revealing version info
- Directory enumeration
- Unnecessary HTTP headers

## 📊 Output Example

```json
{
  "title": "IoT Device Vulnerability Assessment Report",
  "scan_date": "2024-03-02T22:15:30.123456",
  "executive_summary": {
    "total_devices_scanned": 5,
    "total_vulnerabilities": 12,
    "risk_breakdown": {
      "CRITICAL": 4,
      "HIGH": 6,
      "MEDIUM": 2
    }
  },
  "vulnerabilities": [
    {
      "ip": "192.168.1.10",
      "port": 23,
      "service": "Telnet",
      "type": "Insecure_Protocol",
      "risk": "CRITICAL",
      "details": "Telnet transmits credentials in plaintext",
      "remediation": "Disable Telnet, use SSH instead"
    }
  ]
}
```

##  Remediation Examples

### Fix Telnet/FTP Access
```bash
# SSH into device
ssh admin@192.168.1.10

# Disable Telnet
systemctl disable telnetd

# Update SSH key authentication
ssh-keygen -t rsa -b 4096
```

### Update Firmware
1. Visit manufacturer's support page
2. Download latest firmware version
3. Boot into recovery mode
4. Upload firmware file
5. Verify update success

### Change Default Credentials
```
Default: admin/admin
Change to: strong_username/complex_password_32chars
Verify: Test login with new credentials
```

### Enable HTTPS
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes -days 365 -keyout key.pem -out cert.pem

# Configure service to use HTTPS
```

## Scan Configuration

### Aggressive Scan
```python
scanner.discover_iot_devices("192.168.1.0/24")  # Full network
```

### Conservative Scan
```python
target_ports = [22, 80, 443, 8080]  # Specific ports only
```

### Custom Ports
```python
common_ports = {
    8080: {'service': 'HTTP-Alt', 'risk': 'MEDIUM'},
    9200: {'service': 'Elasticsearch', 'risk': 'CRITICAL'},
}
```

##  Best Practices

### Before Testing
- [ ] Obtain written authorization
- [ ] Define scope (network ranges, devices)
- [ ] Document timeline and objectives
- [ ] Inform network administrators
- [ ] Have incident response plan

### During Testing
- [ ] Run scans during maintenance windows
- [ ] Monitor for performance impact
- [ ] Keep detailed logs
- [ ] Don't modify devices (testing only)
- [ ] Respect rate limits

### After Testing
- [ ] Document all findings
- [ ] Prioritize by risk level
- [ ] Provide remediation guidance
- [ ] Schedule follow-up scan
- [ ] Archive reports securely

##  Common Vulnerabilities Found

### Device: TP-Link Router
- Default admin/admin credentials
- HTTP management interface
- Outdated firmware (2.0.1 from 2019)
- Telnet enabled on port 23

### Device: IP Camera
- No authentication on stream
- Firmware version 1.2.3 (vulnerable to CVE-2021-12345)
- Open RTP port 5004
- HTTP only, no HTTPS option

### Device: Smart Bulb Hub
- Default password "bulbs123"
- MQTT broker exposed with no authentication
- Port 1883 open to entire network
- Cloud communication unencrypted

##  IoT Security Resources

- OWASP IoT Top 10: https://owasp.org/www-project-iot/
- ICS-CERT Advisories: https://www.cisa.gov/ics-cert/
- CVE Database: https://cve.mitre.org/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework/
- IoT Security Best Practices: https://www.iot.org/security

## 🔍 Advanced Techniques

### Banner Grabbing
```python
sock = socket.socket()
sock.connect((ip, port))
banner = sock.recv(1024)
print(banner)
```

### Default Credential Testing
```python
credentials = [
    ('admin', 'admin'),
    ('root', 'root'),
    ('admin', '12345')
]
```

### Firmware Extraction
```bash
# Use Binwalk to analyze firmware
binwalk -e firmware.bin
```

### Traffic Analysis
```bash
# Use Wireshark or tcpdump
tcpdump -i eth0 -w iot_traffic.pcap
```

## 📞 Support & Contact

For legitimate cybersecurity research questions:
- Email: animeshbej399@gmail.com

##  License

This tool is provided for educational and authorized testing purposes only.

##  Learning Outcomes

After using this tool, you will understand:
- ✅ Network reconnaissance techniques
- ✅ Port scanning and service identification
- ✅ Vulnerability assessment methodology
- ✅ IoT security best practices
- ✅ Risk assessment and prioritization
- ✅ Remediation strategies
- ✅ Ethical hacking principles

## ⚡ Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run GUI scanner
python3 iot_scanner_gui.py

# Or run CLI
python3 iot_scanner.py
```

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**

 **Offensive Security IoT Device Vulnerability Scanner v1.0**
