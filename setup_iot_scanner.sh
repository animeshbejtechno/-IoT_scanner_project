#!/bin/bash
# IoT Vulnerability Scanner Setup Script
# Offensive Security Tool Installation

echo "🔒 IoT VULNERABILITY SCANNER - SETUP SCRIPT"
echo "==========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Some features require root. Run with sudo for full functionality"
fi

# Install system dependencies
echo -e "\n📦 Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y nmap python3-pip python3-venv git

# Create/activate virtual environment
echo -e "\n🐍 Setting up Python environment..."
cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo -e "\n📚 Installing Python packages..."
pip install --upgrade pip
pip install -r iot_requirements.txt

# Create output directory
mkdir -p reports
mkdir -p logs

# Install desktop launcher
echo -e "\n🖥️  Installing desktop launcher..."
cp iot-scanner.desktop ~/.local/share/applications/
chmod +x iot_scanner_gui.py
chmod +x iot_scanner.py

echo -e "\n✅ Installation Complete!"
echo -e "\n🚀 To launch the IoT Scanner GUI:"
echo -e "   Option 1: python3 iot_scanner_gui.py"
echo -e "   Option 2: Search 'IoT Vulnerability Scanner' in Applications"
echo -e "\n📋 Command line usage:"
echo -e "   python3 iot_scanner.py"
echo -e "\n📖 Documentation:"
echo -e "   cat IOT_SCANNER_README.md"
echo "==========================================="
