#!/bin/bash

# Nmap UI Setup Script
# This script helps set up the Nmap UI application

echo "🚀 Setting up Nmap UI Application"
echo "=================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

echo "✅ Python 3 is available"

# Check if Nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "❌ Nmap is not installed."
    echo "Please install Nmap first:"
    echo "  macOS: brew install nmap"
    echo "  Ubuntu/Debian: sudo apt-get install nmap"
    echo "  CentOS/RHEL: sudo yum install nmap"
    echo "  Fedora: sudo dnf install nmap"
    exit 1
fi

echo "✅ Nmap is available"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install requirements
echo "📥 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "✅ Setup completed successfully!"
echo ""
echo "To run the application:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Start the application: streamlit run nmap_ui.py"
echo "  3. Open your browser to: http://localhost:8501"
echo ""
echo "To test your setup, run: python demo.py"
echo ""
echo "🔍 Happy scanning! (Remember to scan responsibly and legally)"
