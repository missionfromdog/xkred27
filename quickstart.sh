#!/bin/bash

# 🛡️ XKRed27 Security Suite - Quick Start Script
# This script will help you quickly set up and run the security suite

set -e  # Exit on any error

echo "🛡️  XKRed27 Security Suite - Quick Start"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "main.py" ]; then
    print_error "Please run this script from the XKRed27 Security Suite directory"
    exit 1
fi

# Check Python version
print_status "Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    print_error "Python not found. Please install Python 3.7+"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    print_error "Python 3.7+ required. Found: $PYTHON_VERSION"
    exit 1
fi

print_success "Python $PYTHON_VERSION found"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_status "Creating virtual environment..."
    $PYTHON_CMD -m venv venv
    print_success "Virtual environment created"
else
    print_status "Virtual environment already exists"
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip

# Install requirements
print_status "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_success "Dependencies installed"
else
    print_warning "requirements.txt not found. Installing basic dependencies..."
    pip install streamlit pandas numpy psutil streamlit-shadcn-ui streamlit-aggrid
    print_success "Basic dependencies installed"
fi

# Check for required security tools
print_status "Checking required security tools..."

TOOLS_MISSING=()

# Check Nmap
if command -v nmap &> /dev/null; then
    print_success "Nmap found: $(nmap --version | head -n1)"
else
    print_warning "Nmap not found"
    TOOLS_MISSING+=("nmap")
fi

# Check Medusa
if command -v medusa &> /dev/null; then
    print_success "Medusa found: $(medusa -v 2>&1 | head -n1)"
else
    print_warning "Medusa not found"
    TOOLS_MISSING+=("medusa")
fi

# Check Nikto
if command -v nikto &> /dev/null; then
    print_success "Nikto found: $(nikto -Version 2>&1 | head -n1)"
else
    print_warning "Nikto not found (optional)"
fi

# Check Hydra
if command -v hydra &> /dev/null; then
    print_success "Hydra found: $(hydra -v 2>&1 | head -n1)"
else
    print_warning "Hydra not found (optional)"
fi

# Check Gobuster
if command -v gobuster &> /dev/null; then
    print_success "Gobuster found: $(gobuster version 2>&1 | head -n1)"
else
    print_warning "Gobuster not found (optional)"
fi

# Check Tor
if command -v tor &> /dev/null; then
    print_success "Tor found: $(tor --version 2>&1 | head -n1)"
else
    print_warning "Tor not found (optional)"
fi

# Installation instructions for missing tools
if [ ${#TOOLS_MISSING[@]} -gt 0 ]; then
    echo ""
    print_warning "Some required tools are missing. Please install them:"
    echo ""
    
    if [[ " ${TOOLS_MISSING[@]} " =~ " nmap " ]]; then
        echo "📡 Nmap (Network Scanner):"
        echo "   macOS: brew install nmap"
        echo "   Ubuntu: sudo apt install nmap"
        echo "   CentOS: sudo yum install nmap"
        echo ""
    fi
    
    if [[ " ${TOOLS_MISSING[@]} " =~ " medusa " ]]; then
        echo "🔓 Medusa (Brute Force):"
        echo "   macOS: brew install medusa"
        echo "   Ubuntu: sudo apt install medusa"
        echo "   CentOS: sudo yum install medusa"
        echo ""
    fi
    
    echo "For detailed installation instructions, see SETUP.md"
    echo ""
fi

# Check if Streamlit is working
print_status "Testing Streamlit installation..."
if command -v streamlit &> /dev/null; then
    print_success "Streamlit found: $(streamlit --version)"
else
    print_error "Streamlit not found. Please check your installation"
    exit 1
fi

echo ""
print_success "Setup complete! 🎉"
echo ""

# Ask user if they want to start the application
read -p "🚀 Would you like to start the XKRed27 Security Suite now? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Starting XKRed27 Security Suite..."
    echo ""
    echo "🌐 The application will open in your browser at:"
    echo "   Local: http://localhost:8501"
    echo "   Network: http://$(hostname -I | awk '{print $1}'):8501"
    echo ""
    echo "💡 Press Ctrl+C to stop the application"
    echo ""
    
    # Start the application
    streamlit run main.py --server.port 8501
else
    echo ""
    print_status "To start the application later, run:"
    echo "   source venv/bin/activate"
    echo "   streamlit run main.py"
    echo ""
    print_success "Setup complete! Happy security testing! 🛡️✨"
fi
