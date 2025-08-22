#!/bin/bash

# XKRed27 Security Suite Launcher
echo "🛡️ XKRed27 Security Suite"
echo "=========================="

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

# Check if Streamlit is installed
if ! python3 -c "import streamlit" 2>/dev/null; then
    echo "❌ Streamlit is not installed. Installing requirements..."
    pip install -r requirements.txt
fi

echo "🚀 Starting XKRed27 Security Suite..."
echo "The application will open in your browser at http://localhost:8501"
echo ""
echo "Available Tools:"
echo "  🔍 Nmap Network Scanner"
echo "  🔓 Medusa Brute Force"
echo "  🚧 More tools coming soon..."
echo ""
echo "Press Ctrl+C to stop the application"
echo ""

# Start the application
streamlit run main.py
