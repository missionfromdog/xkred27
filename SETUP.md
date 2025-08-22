# 🚀 XKRed27 Security Suite - Setup Guide

This guide will walk you through setting up the XKRed27 Security Suite on your system.

## 📋 **Prerequisites**

### **System Requirements**
- **Operating System**: macOS 10.15+, Ubuntu 18.04+, Windows 10+ (WSL2 recommended)
- **Python**: 3.7 or higher
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 2GB free space
- **Network**: Internet connection for tool installation

### **Required Security Tools**
The following tools must be installed on your system:

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Nmap** | Network scanning | See installation guide below |
| **Medusa** | Brute force attacks | See installation guide below |
| **Nikto** | Web vulnerability scanning | Optional but recommended |
| **Hydra** | Multi-protocol brute force | Optional but recommended |
| **Gobuster** | Directory/file enumeration | Optional but recommended |
| **Tor** | Network anonymization | Optional but recommended |

---

## 🛠️ **Installation by Operating System**

### **macOS Installation**

#### **1. Install Homebrew (if not already installed)**
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### **2. Install Security Tools**
```bash
# Core tools (required)
brew install nmap
brew install medusa

# Additional tools (recommended)
brew install nikto
brew install hydra
brew install gobuster
brew install tor

# Start Tor service
brew services start tor
```

#### **3. Verify Installation**
```bash
nmap --version
medusa -v
nikto -Version
hydra -v
gobuster version
tor --version
```

---

### **Ubuntu/Debian Installation**

#### **1. Update Package Lists**
```bash
sudo apt update
sudo apt upgrade -y
```

#### **2. Install Security Tools**
```bash
# Core tools (required)
sudo apt install -y nmap
sudo apt install -y medusa

# Additional tools (recommended)
sudo apt install -y nikto
sudo apt install -y hydra
sudo apt install -y gobuster
sudo apt install -y tor

# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor
```

#### **3. Verify Installation**
```bash
nmap --version
medusa -v
nikto -Version
hydra -v
gobuster version
tor --version
```

---

### **CentOS/RHEL/Fedora Installation**

#### **1. Update Package Lists**
```bash
# CentOS/RHEL
sudo yum update -y

# Fedora
sudo dnf update -y
```

#### **2. Install Security Tools**
```bash
# Core tools (required)
sudo yum install -y nmap medusa    # CentOS/RHEL
sudo dnf install -y nmap medusa    # Fedora

# Additional tools (recommended)
sudo yum install -y nikto hydra gobuster tor    # CentOS/RHEL
sudo dnf install -y nikto hydra gobuster tor    # Fedora

# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor
```

#### **3. Verify Installation**
```bash
nmap --version
medusa -v
nikto -Version
hydra -v
gobuster version
tor --version
```

---

### **Windows Installation**

#### **1. Install WSL2 (Recommended)**
```powershell
# Enable WSL
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Restart computer, then install WSL2
wsl --install
```

#### **2. Install Ubuntu on WSL2**
```powershell
wsl --install -d Ubuntu
```

#### **3. Follow Ubuntu Installation Steps**
Once WSL2 Ubuntu is running, follow the Ubuntu installation steps above.

#### **4. Alternative: Native Windows Installation**
- **Nmap**: Download from [nmap.org](https://nmap.org/download.html)
- **Other tools**: Use WSL2 or Linux VM for better compatibility

---

## 🐍 **Python Environment Setup**

### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/XKRed27-Security-Suite.git
cd XKRed27-Security-Suite
```

### **2. Create Virtual Environment**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### **3. Install Python Dependencies**
```bash
# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt
```

### **4. Verify Python Setup**
```bash
# Check Python version
python --version

# Check Streamlit
streamlit --version

# Check installed packages
pip list
```

---

## 🚀 **Running the Application**

### **1. Basic Startup**
```bash
# Make sure virtual environment is activated
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# Start the application
streamlit run main.py
```

### **2. Advanced Startup Options**
```bash
# Custom port
streamlit run main.py --server.port 8501

# Headless mode (no browser auto-open)
streamlit run main.py --server.headless true

# External access (be careful with this)
streamlit run main.py --server.address 0.0.0.0

# Custom configuration
streamlit run main.py --server.port 8501 --server.headless true
```

### **3. Access the Application**
- **Local**: http://localhost:8501
- **Network**: http://your-ip:8501
- **External**: http://your-external-ip:8501 (if configured)

---

## ⚙️ **Configuration**

### **1. Streamlit Configuration**
Create `.streamlit/config.toml` for custom settings:
```toml
[server]
port = 8501
headless = true
address = "localhost"

[theme]
primaryColor = "#3b82f6"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f8fafc"
textColor = "#0f172a"
```

### **2. Tool Configuration**
Each security tool can be configured through the web interface:
- **Thread counts**: Adjust based on your system capabilities
- **Timeouts**: Set appropriate values for your network
- **Wordlists**: Use custom wordlists for better results

### **3. Performance Tuning**
```bash
# Monitor system resources
htop  # Linux/macOS
top   # Basic monitoring

# Check network interfaces
ifconfig  # Linux/macOS
ipconfig  # Windows
```

---

## 🔐 **Security Configuration**

### **1. Privilege Management**
Some tools require elevated privileges:
```bash
# Run with sudo (be careful!)
sudo streamlit run main.py

# Or use built-in authentication in the app
```

### **2. Network Security**
- **Firewall**: Configure your firewall to allow the application
- **VPN**: Use VPN for additional privacy
- **Tor**: Enable Tor for anonymous operations

### **3. Access Control**
- **Local Access**: Only allow localhost access by default
- **Network Access**: Restrict to trusted networks only
- **Authentication**: Use strong passwords if exposing externally

---

## 🧪 **Testing Your Installation**

### **1. Basic Functionality Test**
```bash
# Test Nmap
nmap -sn 127.0.0.1

# Test Medusa
medusa -h

# Test Nikto
nikto -h

# Test Hydra
hydra -h

# Test Gobuster
gobuster -h
```

### **2. Application Test**
1. Start the application: `streamlit run main.py`
2. Navigate to http://localhost:8501
3. Test each tool with safe targets (localhost, your own network)
4. Verify reports and exports work correctly

### **3. Performance Test**
1. Run a network discovery scan
2. Monitor system resources
3. Check for any errors or warnings
4. Verify all features work as expected

---

## 🚨 **Troubleshooting**

### **Common Issues**

#### **"Command not found" Errors**
```bash
# Check if tools are in PATH
which nmap
which medusa
which nikto

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
export PATH=$PATH:/opt/homebrew/bin  # macOS Apple Silicon
```

#### **Permission Denied Errors**
```bash
# Check file permissions
ls -la /usr/bin/nmap
ls -la /usr/bin/medusa

# Fix permissions if needed
sudo chmod +x /usr/bin/nmap
sudo chmod +x /usr/bin/medusa
```

#### **Port Already in Use**
```bash
# Find process using port
lsof -i :8501
netstat -tulpn | grep 8501

# Kill process
pkill -f streamlit

# Or use different port
streamlit run main.py --server.port 8502
```

#### **Python Import Errors**
```bash
# Check virtual environment
which python
pip list

# Reinstall requirements
pip install -r requirements.txt --force-reinstall
```

#### **Tool-Specific Issues**

**Nmap Issues:**
```bash
# Check Nmap installation
nmap --version

# Test basic functionality
nmap -sn 127.0.0.1

# Check for privilege issues
sudo nmap -sS 127.0.0.1
```

**Medusa Issues:**
```bash
# Check Medusa installation
medusa -v

# Test basic functionality
medusa -h

# Check for missing dependencies
ldd $(which medusa)
```

**Streamlit Issues:**
```bash
# Check Streamlit installation
streamlit --version

# Clear Streamlit cache
streamlit cache clear

# Check for configuration issues
streamlit config show
```

---

## 📚 **Additional Resources**

### **Documentation**
- **Nmap**: [nmap.org/book](https://nmap.org/book/)
- **Medusa**: [foofus.net/medusa](https://foofus.net/medusa/)
- **Nikto**: [cirt.net/Nikto2](https://cirt.net/Nikto2)
- **Streamlit**: [docs.streamlit.io](https://docs.streamlit.io/)

### **Community Support**
- **GitHub Issues**: Report bugs and request features
- **Security Forums**: Get help from the security community
- **Tool Mailing Lists**: Subscribe to tool-specific lists

### **Learning Resources**
- **Network Security**: [SANS Network Security](https://www.sans.org/cyber-security-courses/network-security/)
- **Penetration Testing**: [Offensive Security](https://www.offensive-security.com/)
- **Web Security**: [OWASP](https://owasp.org/)

---

## ✅ **Verification Checklist**

Before considering your installation complete, verify:

- [ ] **Security tools installed** and working
- [ ] **Python environment** set up correctly
- [ ] **Dependencies installed** without errors
- [ ] **Application starts** without errors
- [ ] **All tools accessible** through the interface
- [ ] **Reports generate** correctly
- [ ] **Exports work** as expected
- [ ] **Performance monitoring** functional
- [ ] **Error handling** working properly
- [ ] **Security warnings** displayed correctly

---

## 🎯 **Next Steps**

After successful installation:

1. **Read the README**: Understand all features and capabilities
2. **Test with safe targets**: Use localhost and your own networks
3. **Learn the tools**: Understand each security tool's capabilities
4. **Practice responsibly**: Follow ethical hacking guidelines
5. **Contribute**: Report bugs and suggest improvements

---

## 🆘 **Getting Help**

If you encounter issues:

1. **Check this guide** for common solutions
2. **Search GitHub issues** for similar problems
3. **Check tool documentation** for specific errors
4. **Ask the community** for help
5. **Report bugs** with detailed information

---

**Happy Security Testing! 🛡️✨**
