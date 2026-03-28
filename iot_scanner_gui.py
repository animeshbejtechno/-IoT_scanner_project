#!/usr/bin/env python3
"""
IoT Vulnerability Scanner - GUI Version
Professional tool for offensive security and penetration testing
"""

import sys
import json
import threading
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTextEdit, QLineEdit, 
                             QLabel, QMessageBox, QProgressBar, QStatusBar,
                             QTableWidget, QTableWidgetItem, QTabWidget, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QColor, QFont

from iot_scanner import IOTVulnerabilityScanner

class ScannerThread(QThread):
    """Background thread for scanning"""
    progress = pyqtSignal(str)
    scan_complete = pyqtSignal(dict)
    
    def __init__(self, scanner, network_range, target_ip):
        super().__init__()
        self.scanner = scanner
        self.network_range = network_range
        self.target_ip = target_ip
    
    def run(self):
        """Run the scan"""
        try:
            self.progress.emit("🔍 Starting network discovery...")
            devices = self.scanner.discover_iot_devices(self.network_range)
            
            # Store discovered devices
            self.scanner.scan_results['devices_found'] = devices
            self.progress.emit(f"✅ Found {len(devices)} devices on network")
            
            for device in devices:
                self.progress.emit(f"🔐 Scanning device: {device['ip']} ({device.get('hostname', 'Unknown')})")
                vulns = self.scanner.scan_device(device['ip'])
                self.scanner.scan_results['vulnerabilities'].extend(vulns)
            
            self.progress.emit("✅ Scan completed!")
            self.scan_complete.emit(self.scanner.scan_results)
        
        except Exception as e:
            self.progress.emit(f"❌ Error: {str(e)}")

class IOTScannerGUI(QMainWindow):
    """GUI for IoT Vulnerability Scanner"""
    
    def __init__(self):
        super().__init__()
        self.scanner = IOTVulnerabilityScanner()
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        self.setWindowTitle("🔒 IoT Device Vulnerability Scanner - Offensive Security")
        self.setGeometry(100, 100, 1400, 900)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Offensive Security IoT Device Vulnerability Scanner")
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header_label.setFont(header_font)
        header_label.setStyleSheet("color: #cc0000; padding: 10px;")
        main_layout.addWidget(header_label)
        
        # Disclaimer
        disclaimer = QLabel("⚠️  For authorized security testing ONLY - Unauthorized scanning is illegal")
        disclaimer.setStyleSheet("color: #ff6600; background-color: #ffffcc; padding: 8px; border-radius: 5px;")
        main_layout.addWidget(disclaimer)
        
        # Input section
        input_layout = QHBoxLayout()
        
        input_layout.addWidget(QLabel("Network Range:"))
        self.network_input = QLineEdit("192.168.1.0/24")
        input_layout.addWidget(self.network_input)
        
        input_layout.addWidget(QLabel("Target Device:"))
        self.target_input = QLineEdit("192.168.1.1")
        input_layout.addWidget(self.target_input)
        
        scan_btn = QPushButton("🔍 Start Scan")
        scan_btn.clicked.connect(self.start_scan)
        scan_btn.setStyleSheet("background-color: #cc0000; color: white; font-weight: bold; padding: 8px;")
        input_layout.addWidget(scan_btn)
        
        report_btn = QPushButton("📊 Generate Report")
        report_btn.clicked.connect(self.generate_report)
        report_btn.setStyleSheet("background-color: #0066cc; color: white; font-weight: bold; padding: 8px;")
        input_layout.addWidget(report_btn)
        
        main_layout.addLayout(input_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Tabs for different views
        self.tabs = QTabWidget()
        
        # Tab 1: Scan Output
        output_widget = QWidget()
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("background-color: #1a1a1a; color: #00ff00; font-family: monospace;")
        output_layout.addWidget(self.output_text)
        output_widget.setLayout(output_layout)
        self.tabs.addTab(output_widget, "📋 Scan Output")
        
        # Tab 2: Vulnerabilities Table
        vuln_widget = QWidget()
        vuln_layout = QVBoxLayout()
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(['IP', 'Port', 'Service', 'Vulnerability', 'Risk Level'])
        vuln_layout.addWidget(self.vuln_table)
        vuln_widget.setLayout(vuln_layout)
        self.tabs.addTab(vuln_widget, "🚨 Vulnerabilities")
        
        # Tab 3: Device Details
        device_widget = QWidget()
        device_layout = QVBoxLayout()
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(3)
        self.device_table.setHorizontalHeaderLabels(['IP Address', 'Hostname', 'Open Ports'])
        device_layout.addWidget(self.device_table)
        device_widget.setLayout(device_layout)
        self.tabs.addTab(device_widget, "🖥️  Devices")
        
        # Tab 4: Remediation Guide
        remedy_widget = QWidget()
        remedy_layout = QVBoxLayout()
        self.remedy_text = QTextEdit()
        self.remedy_text.setReadOnly(True)
        self.remedy_text.setStyleSheet("background-color: #f0f0f0; font-family: monospace;")
        remedy_layout.addWidget(self.remedy_text)
        remedy_widget.setLayout(remedy_layout)
        self.tabs.addTab(remedy_widget, "🔧 Remediation")
        
        main_layout.addWidget(self.tabs)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("🟢 Ready")
        
        central_widget.setLayout(main_layout)
        
        # Print initial info
        self.output_text.setText("""
╔════════════════════════════════════════════════════════════════════════════╗
║         IoT DEVICE VULNERABILITY SCANNER - OFFENSIVE SECURITY              ║
║                    For Authorized Testing Only                            ║
╚════════════════════════════════════════════════════════════════════════════╝

✅ Scanner Features:
  • Network device discovery (ICMP/Nmap)
  • Port scanning and service detection
  • Vulnerability assessment
  • Default credential testing
  • Insecure protocol detection
  • Comprehensive reporting

📋 Scanning Capabilities:
  • Detects: Smart cameras, routers, smart bulbs, home automation
  • Tests: Weak credentials, insecure protocols (HTTP, Telnet, FTP)
  • Checks: Outdated firmware, open ports, missing authentication
  • Assesses: Risk levels and attack scenarios

⚠️  ETHICAL & LEGAL:
  • Only use on networks/devices you own or have explicit permission
  • Unauthorized access is a federal crime
  • Keep detailed records of all authorized testing
  • Follow your organization's security policies

🚀 Getting Started:
  1. Enter your network range (e.g., 192.168.1.0/24)
  2. Specify target device or leave for full scan
  3. Click "Start Scan"
  4. Review vulnerabilities in the "Vulnerabilities" tab
  5. Generate report for documentation

""")
    
    def start_scan(self):
        """Start vulnerability scan"""
        network_range = self.network_input.text()
        target_ip = self.target_input.text()
        
        if not network_range or not target_ip:
            QMessageBox.warning(self, "Input Error", "Please enter network range and target IP")
            return
        
        self.output_text.setText("🔍 Scan starting...\n" + "="*80 + "\n")
        self.progress_bar.setVisible(True)
        
        self.scanner = IOTVulnerabilityScanner()
        self.scanner_thread = ScannerThread(self.scanner, network_range, target_ip)
        self.scanner_thread.progress.connect(self.update_progress)
        self.scanner_thread.scan_complete.connect(self.scan_finished)
        self.scanner_thread.start()
    
    def update_progress(self, message):
        """Update progress"""
        self.output_text.append(message)
        self.status_bar.showMessage(message)
    
    def scan_finished(self, results):
        """Scan finished"""
        self.progress_bar.setVisible(False)
        self.output_text.append("\n✅ Scan Complete!\n")
        
        # Display devices first
        device_count = len(results.get('devices_found', []))
        vuln_count = len(results.get('vulnerabilities', []))
        self.output_text.append(f"📊 Scan Summary: {device_count} devices, {vuln_count} vulnerabilities\n")
        self.output_text.append(f"📋 Devices list: {results.get('devices_found', [])}\n")
        
        # Display vulnerabilities
        self.display_vulnerabilities(results)
        self.display_devices(results)
        self.display_remediation()
        
        self.status_bar.showMessage(f"✅ Scan finished - {device_count} devices found")
    
    def display_vulnerabilities(self, results):
        """Display vulnerabilities table"""
        self.vuln_table.setRowCount(0)
        
        vulnerabilities = results.get('vulnerabilities', [])
        if not vulnerabilities:
            self.output_text.append("\n✅ No vulnerabilities found - devices have good security!\n")
            return
        
        for vuln in vulnerabilities:
            row = self.vuln_table.rowCount()
            self.vuln_table.insertRow(row)
            
            # Get IP from vuln or use 'N/A'
            ip = vuln.get('ip', 'N/A')
            self.vuln_table.setItem(row, 0, QTableWidgetItem(ip))
            self.vuln_table.setItem(row, 1, QTableWidgetItem(str(vuln.get('port', 'N/A'))))
            self.vuln_table.setItem(row, 2, QTableWidgetItem(vuln.get('service', 'Unknown')))
            self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln.get('type', 'Unknown')))
            
            risk_item = QTableWidgetItem(vuln.get('risk', 'UNKNOWN'))
            if vuln.get('risk') == 'CRITICAL':
                risk_item.setForeground(QColor('#cc0000'))
            elif vuln.get('risk') == 'HIGH':
                risk_item.setForeground(QColor('#ff6600'))
            elif vuln.get('risk') == 'MEDIUM':
                risk_item.setForeground(QColor('#ffcc00'))
            
            self.vuln_table.setItem(row, 4, risk_item)
    
    def display_devices(self, results):
        """Display discovered devices"""
        self.device_table.setRowCount(0)
        
        for device in results.get('devices_found', []):
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            
            self.device_table.setItem(row, 0, QTableWidgetItem(device.get('ip', 'N/A')))
            self.device_table.setItem(row, 1, QTableWidgetItem(device.get('hostname', 'Unknown')))
            ports = ', '.join(map(str, device.get('open_ports', [])))
            self.device_table.setItem(row, 2, QTableWidgetItem(ports))
    
    def display_remediation(self):
        """Display remediation guidance"""
        guidance = self.scanner.get_remediation_guidance()
        text = "🔧 REMEDIATION GUIDANCE\n" + "="*80 + "\n\n"
        
        for risk_level, steps in guidance.items():
            text += f"{risk_level} Priority:\n"
            for step in steps:
                text += f"  • {step}\n"
            text += "\n"
        
        self.remedy_text.setText(text)
    
    def generate_report(self):
        """Generate JSON report"""
        report = self.scanner.generate_report()
        QMessageBox.information(self, "Report Generated", 
                              "✅ Report saved as iot_scan_report.json")

def main():
    app = QApplication(sys.argv)
    window = IOTScannerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
