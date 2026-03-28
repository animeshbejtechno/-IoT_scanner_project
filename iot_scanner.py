#!/usr/bin/env python3
"""
Offensive Security IoT Device Vulnerability Scanner
A comprehensive tool for identifying security weaknesses in IoT devices
For ethical hacking, penetration testing, and cybersecurity research purposes ONLY

Disclaimer: This tool is designed for authorized security testing only.
Unauthorized scanning of networks or devices is illegal.
"""

import sys
import json
import os
import socket
import subprocess
from datetime import datetime
from collections import defaultdict

# Network scanning libraries
try:
    import nmap
except ImportError:
    nmap = None

import requests
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
import threading
import queue

class IOTVulnerabilityScanner:
    """Main IoT Vulnerability Scanner"""
    
    def __init__(self):
        self.vulnerabilities_db = self.load_vulnerability_database()
        self.default_credentials = self.load_default_credentials()
        self.common_ports = self.load_common_iot_ports()
        self.scan_results = {
            'devices_found': [],
            'vulnerabilities': [],
            'scan_date': datetime.now().isoformat(),
            'risk_summary': defaultdict(int)
        }
    
    def load_vulnerability_database(self):
        """Load known IoT vulnerabilities"""
        return {
            'HTTP': {
                'risk': 'HIGH',
                'description': 'Insecure HTTP protocol (no encryption)',
                'mitigation': 'Use HTTPS with valid SSL certificates'
            },
            'Telnet': {
                'risk': 'CRITICAL',
                'description': 'Telnet protocol transmits data in plaintext',
                'mitigation': 'Disable Telnet, use SSH instead'
            },
            'FTP': {
                'risk': 'CRITICAL',
                'description': 'FTP transmits credentials and data in plaintext',
                'mitigation': 'Use SFTP or disable FTP service'
            },
            'SSH_v1': {
                'risk': 'HIGH',
                'description': 'SSH version 1 has known security flaws',
                'mitigation': 'Upgrade to SSH version 2'
            },
            'Default_Credentials': {
                'risk': 'CRITICAL',
                'description': 'Device using default/weak credentials',
                'mitigation': 'Change all default passwords immediately'
            },
            'No_Authentication': {
                'risk': 'CRITICAL',
                'description': 'Service running without authentication',
                'mitigation': 'Enable authentication mechanisms'
            },
            'SNMP_Public': {
                'risk': 'HIGH',
                'description': 'SNMP running with public community string',
                'mitigation': 'Change SNMP community strings and disable if unused'
            },
            'UPnP_Enabled': {
                'risk': 'MEDIUM',
                'description': 'UPnP can be exploited for port forwarding',
                'mitigation': 'Disable UPnP if not required'
            },
            'Old_Firmware': {
                'risk': 'HIGH',
                'description': 'Outdated firmware with known vulnerabilities',
                'mitigation': 'Update device firmware to latest version'
            },
            'Open_Port': {
                'risk': 'MEDIUM',
                'description': 'Unnecessary port is open',
                'mitigation': 'Close unused ports and services'
            }
        }
    
    def load_default_credentials(self):
        """Load common default credentials for IoT devices"""
        return {
            'admin/admin': ['Router', 'Camera', 'Switch'],
            'admin/password': ['Router', 'NVR'],
            'root/root': ['Linux devices', 'Embedded systems'],
            'root/12345': ['Some routers'],
            'admin/12345': ['Various devices'],
            'guest/guest': ['Networking equipment'],
            'ubnt/ubnt': ['Ubiquiti devices'],
            'admin/123456': ['Various IoT devices'],
            'none/none': ['Devices with no password'],
            'admin/admin123': ['Multiple devices']
        }
    
    def load_common_iot_ports(self):
        """Load common IoT device ports"""
        return {
            23: {'service': 'Telnet', 'risk': 'CRITICAL'},
            21: {'service': 'FTP', 'risk': 'CRITICAL'},
            80: {'service': 'HTTP', 'risk': 'HIGH'},
            443: {'service': 'HTTPS', 'risk': 'LOW'},
            22: {'service': 'SSH', 'risk': 'LOW'},
            8080: {'service': 'HTTP-Alt', 'risk': 'MEDIUM'},
            8443: {'service': 'HTTPS-Alt', 'risk': 'LOW'},
            162: {'service': 'SNMP-Trap', 'risk': 'MEDIUM'},
            161: {'service': 'SNMP', 'risk': 'HIGH'},
            1883: {'service': 'MQTT', 'risk': 'MEDIUM'},
            5353: {'service': 'mDNS', 'risk': 'MEDIUM'},
            5357: {'service': 'WSD', 'risk': 'MEDIUM'},
            10000: {'service': 'Webmin', 'risk': 'HIGH'},
            9200: {'service': 'Elasticsearch', 'risk': 'CRITICAL'},
            27017: {'service': 'MongoDB', 'risk': 'CRITICAL'},
            6379: {'service': 'Redis', 'risk': 'CRITICAL'},
            5900: {'service': 'VNC', 'risk': 'HIGH'},
            3389: {'service': 'RDP', 'risk': 'MEDIUM'},
            445: {'service': 'SMB', 'risk': 'HIGH'},
            139: {'service': 'NetBIOS', 'risk': 'HIGH'},
            69: {'service': 'TFTP', 'risk': 'HIGH'},
            53: {'service': 'DNS', 'risk': 'LOW'},
        }
    
    def discover_iot_devices(self, network_range):
        """Discover IoT devices on a network"""
        print(f"\n🔍 Scanning network: {network_range}")
        print("=" * 80)
        
        devices = []
        
        if nmap:
            try:
                nm = nmap.PortScanner()
                print(f"📡 Starting nmap scan...")
                nm.scan(network_range, '-p 22,23,80,443,8080,161,5357', '-T4')
                
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        device_info = {
                            'ip': host,
                            'hostname': self.get_hostname(host),
                            'open_ports': [],
                            'services': []
                        }
                        
                        for proto in nm[host].all_protocols():
                            ports = nm[host][proto].keys()
                            for port in ports:
                                if nm[host][proto][port]['state'] == 'open':
                                    device_info['open_ports'].append(port)
                        
                        # Add all devices, even without open ports in this scan
                        devices.append(device_info)
                        if device_info['open_ports']:
                            print(f"✅ Found device: {host} - Ports: {device_info['open_ports']}")
                        else:
                            print(f"✅ Found device: {host}")
            except Exception as e:
                print(f"⚠️ Nmap scanning failed: {e}")
        else:
            print("⚠️ Nmap not installed. Installing basic ICMP ping...")
            devices = self.basic_network_discovery(network_range)
        
        return devices
    
    def basic_network_discovery(self, network_range):
        """Basic network discovery using ping"""
        devices = []
        
        # Parse the network range
        if '/' in network_range:
            base_ip = network_range.split('/')[0]
            base_parts = base_ip.split('.')
            base = '.'.join(base_parts[:-1])
        else:
            base_parts = network_range.split('.')
            base = '.'.join(base_parts[:-1])
        
        print(f"📡 Scanning subnet: {base}.0/24")
        
        for i in range(1, 256):
            ip = f'{base}.{i}'
            try:
                response = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                        capture_output=True, timeout=3)
                if response.returncode == 0:
                    device_info = {
                        'ip': ip,
                        'hostname': self.get_hostname(ip),
                        'open_ports': [],
                        'services': []
                    }
                    devices.append(device_info)
                    print(f"✅ Found device: {ip}")
            except Exception as e:
                pass
        
        return devices
    
    def get_hostname(self, ip):
        """Get hostname from IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
    
    def scan_device(self, ip_address, ports_to_scan=None):
        """Scan a specific device for vulnerabilities"""
        print(f"\n🔐 Scanning device: {ip_address}")
        print("-" * 80)
        
        if ports_to_scan is None:
            ports_to_scan = list(self.common_ports.keys())
        
        device_vulns = []
        
        for port in ports_to_scan:
            if self.is_port_open(ip_address, port):
                print(f"  ✅ Port {port} OPEN - {self.common_ports[port]['service']}")
                
                vulns = self.check_port_vulnerability(ip_address, port)
                device_vulns.extend(vulns)
        
        return device_vulns
    
    def is_port_open(self, ip, port, timeout=3):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_port_vulnerability(self, ip, port):
        """Check specific port for vulnerabilities"""
        vulnerabilities = []
        service = self.common_ports[port]['service']
        
        # Check for insecure protocols
        if service == 'Telnet':
            vulnerabilities.append({
                'ip': ip,
                'port': port,
                'service': service,
                'type': 'Telnet',
                'risk': 'CRITICAL',
                'details': 'Telnet transmits credentials in plaintext'
            })
        
        elif service == 'FTP':
            vulnerabilities.append({
                'ip': ip,
                'port': port,
                'service': service,
                'type': 'FTP',
                'risk': 'CRITICAL',
                'details': 'FTP transmits data and credentials unencrypted'
            })
        
        elif service == 'HTTP':
            # Check for weak HTTP headers and default creds
            http_vulns = self.scan_http_service(ip, port)
            vulnerabilities.extend(http_vulns)
        
        elif service == 'SNMP':
            snmp_vulns = self.scan_snmp(ip, port)
            vulnerabilities.extend(snmp_vulns)
        
        elif service == 'SSH':
            # Check SSH version
            vulnerabilities.extend(self.check_ssh_version(ip, port))
        
        return vulnerabilities
    
    def scan_http_service(self, ip, port):
        """Scan HTTP/HTTPS service"""
        vulnerabilities = []
        protocol = 'https' if port == 443 else 'http'
        url = f'{protocol}://{ip}:{port}'
        
        try:
            response = requests.get(url, timeout=3, verify=False)
            
            # Check for default credentials
            default_found = self.test_default_credentials(url)
            if default_found:
                vulnerabilities.append({
                    'ip': ip,
                    'port': port,
                    'service': 'HTTP',
                    'type': 'Default_Credentials',
                    'risk': 'CRITICAL',
                    'details': f'Default credentials found: {default_found}'
                })
            
            # Check headers
            if 'Server' in response.headers:
                server = response.headers['Server']
                vulnerabilities.append({
                    'ip': ip,
                    'port': port,
                    'service': 'HTTP',
                    'type': 'Server_Disclosure',
                    'risk': 'MEDIUM',
                    'details': f'Server information disclosed: {server}'
                })
            
            # Check for HTTPS redirect
            if protocol == 'http' and 'Location' not in response.headers:
                vulnerabilities.append({
                    'ip': ip,
                    'port': port,
                    'service': 'HTTP',
                    'type': 'No_HTTPS_Redirect',
                    'risk': 'HIGH',
                    'details': 'No automatic HTTPS redirect configured'
                })
        
        except requests.exceptions.SSLError:
            vulnerabilities.append({
                'ip': ip,
                'port': port,
                'service': 'HTTPS',
                'type': 'Invalid_SSL',
                'risk': 'HIGH',
                'details': 'Invalid or self-signed SSL certificate'
            })
        except:
            pass
        
        return vulnerabilities
    
    def test_default_credentials(self, url):
        """Test for default credentials"""
        for cred, devices in self.default_credentials.items():
            if ':' in cred:
                username, password = cred.split(':')
                try:
                    response = requests.get(url, auth=HTTPBasicAuth(username, password),
                                          timeout=2, verify=False)
                    if response.status_code == 200:
                        return f'{username}:{password}'
                except:
                    pass
        return None
    
    def scan_snmp(self, ip, port):
        """Scan SNMP service"""
        vulnerabilities = []
        
        try:
            # Basic SNMP check
            vulnerabilities.append({
                'ip': ip,
                'port': port,
                'service': 'SNMP',
                'type': 'SNMP_Public',
                'risk': 'HIGH',
                'details': 'SNMP service detected - check for weak community strings'
            })
        except:
            pass
        
        return vulnerabilities
    
    def check_ssh_version(self, ip, port):
        """Check SSH version"""
        vulnerabilities = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode()
            sock.close()
            
            if 'SSH-1' in banner:
                vulnerabilities.append({
                    'ip': ip,
                    'port': port,
                    'service': 'SSH',
                    'type': 'SSH_v1',
                    'risk': 'HIGH',
                    'details': f'SSH version 1 detected: {banner.strip()}'
                })
        except:
            pass
        
        return vulnerabilities
    
    def generate_report(self, output_file='iot_scan_report.json'):
        """Generate comprehensive vulnerability report"""
        print("\n" + "=" * 80)
        print("📊 GENERATING VULNERABILITY REPORT")
        print("=" * 80)
        
        # Categorize vulnerabilities by risk
        for vuln in self.scan_results['vulnerabilities']:
            risk = vuln.get('risk', 'UNKNOWN')
            self.scan_results['risk_summary'][risk] += 1
        
        report = {
            'title': 'IoT Device Vulnerability Assessment Report',
            'disclaimer': 'This report is for authorized security testing only',
            'scan_date': self.scan_results['scan_date'],
            'executive_summary': {
                'total_devices_scanned': len(self.scan_results['devices_found']),
                'total_vulnerabilities': len(self.scan_results['vulnerabilities']),
                'risk_breakdown': dict(self.scan_results['risk_summary'])
            },
            'devices': self.scan_results['devices_found'],
            'vulnerabilities': self.scan_results['vulnerabilities'],
            'remediation_guidance': self.get_remediation_guidance()
        }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Report saved to: {output_file}")
        
        # Print summary
        print(f"\n📈 SCAN SUMMARY:")
        print(f"  • Devices Found: {report['executive_summary']['total_devices_scanned']}")
        print(f"  • Vulnerabilities: {report['executive_summary']['total_vulnerabilities']}")
        print(f"  • Critical: {report['executive_summary']['risk_breakdown'].get('CRITICAL', 0)}")
        print(f"  • High: {report['executive_summary']['risk_breakdown'].get('HIGH', 0)}")
        print(f"  • Medium: {report['executive_summary']['risk_breakdown'].get('MEDIUM', 0)}")
        
        return report
    
    def get_remediation_guidance(self):
        """Get remediation guidance"""
        return {
            'CRITICAL': [
                'Address immediately - system is at critical risk',
                'Change all default credentials',
                'Disable insecure protocols (Telnet, FTP)',
                'Apply latest security patches'
            ],
            'HIGH': [
                'Address within 48 hours',
                'Update firmware to latest version',
                'Configure HTTPS and disable HTTP where possible',
                'Enable authentication on all services'
            ],
            'MEDIUM': [
                'Address within 1-2 weeks',
                'Review and restrict network access',
                'Monitor for suspicious activity',
                'Document all devices and services'
            ]
        }

def main():
    """Main execution"""
    print("\n" + "=" * 80)
    print("🔒 OFFENSIVE SECURITY IoT DEVICE VULNERABILITY SCANNER")
    print("=" * 80)
    print("⚠️  DISCLAIMER: For authorized security testing ONLY")
    print("    Unauthorized scanning is illegal and unethical")
    print("=" * 80)
    
    scanner = IOTVulnerabilityScanner()
    
    # Example usage
    network_range = "192.168.1.0/24"  # Change to your network
    test_ip = "192.168.1.1"  # Change to target device
    
    print(f"\n📋 Scanner Configuration:")
    print(f"  • Network Range: {network_range}")
    print(f"  • Test Device: {test_ip}")
    print(f"  • Known Vulnerabilities Database: {len(scanner.vulnerabilities_db)} entries")
    print(f"  • Default Credentials: {len(scanner.default_credentials)} combinations")
    
    # Discover devices
    devices = scanner.discover_iot_devices(network_range)
    scanner.scan_results['devices_found'] = devices
    
    # Scan each device
    for device in devices:
        vulns = scanner.scan_device(device['ip'])
        scanner.scan_results['vulnerabilities'].extend(vulns)
    
    # Generate report
    scanner.generate_report()
    
    print("\n✅ Scan completed!")

if __name__ == "__main__":
    main()
