# 🛡️ XKRed27 Security Suite

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.48+-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)

**A modern, professional security testing platform with beautiful shadcn-inspired UI**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Tools](#-tools) • [Screenshots](#-screenshots)

</div>

---

## ✨ **What is XKRed27 Security Suite?**

XKRed27 Security Suite is a **comprehensive, enterprise-grade security testing platform** that brings together the world's most powerful security tools into a single, beautiful web interface. Built with modern design principles and the shadcn design system, it provides security professionals, penetration testers, and network administrators with an intuitive way to access advanced security tools.

### 🎯 **Key Benefits**
- **🎨 Modern UI/UX**: Beautiful shadcn-inspired design with professional aesthetics
- **🔧 Multi-Tool Integration**: 7+ security tools in one unified platform
- **📱 Responsive Design**: Works perfectly on desktop, tablet, and mobile
- **🔐 Enterprise Security**: Built-in privilege management and secure authentication
- **📊 Professional Reporting**: Export results in multiple formats with beautiful styling
- **⚡ High Performance**: Optimized for speed with real-time monitoring

---

## 🚀 **Features**

### 🏠 **Modern Web Interface**
- **shadcn Design System**: Professional, clean interface inspired by modern design principles
- **Responsive Layout**: Adaptive design that works on all devices
- **Dark/Light Themes**: Professional color schemes for different environments
- **Interactive Elements**: Hover effects, smooth animations, and modern UI components

### 🔧 **Comprehensive Tool Suite**

| Tool | Purpose | Features |
|------|---------|----------|
| 🌐 **Network Discovery** | Host enumeration | Ping scanning, network mapping, host discovery |
| 🔍 **Nmap Scanner** | Port scanning & enumeration | TCP/UDP scans, OS detection, service discovery |
| 🔓 **Medusa Brute Force** | Authentication testing | Multi-protocol support, parallel processing |
| 🔍 **Nikto Web Scanner** | Web vulnerability scanning | 6700+ checks, SSL support, custom tuning |
| 🔒 **Hydra Multi-Protocol** | Network login cracking | 22+ protocols, high-speed processing |
| 🔍 **Gobuster Scanner** | Directory/file enumeration | 5 modes: dir, dns, vhost, fuzz, S3 |
| 🕵️ **AnonSurf** | Network anonymization | Tor integration, VPN support, privacy protection |

### 📊 **Professional Reporting**
- **HTML Reports**: Beautiful, styled reports with tables and formatting
- **JSON Export**: Structured data for programmatic processing
- **Raw Output**: Original tool output for command-line users
- **Real-time Progress**: Live updates during operations

### 🔐 **Enterprise Security Features**
- **Built-in Sudo Support**: Automatic privilege management
- **Secure Authentication**: Password input with memory protection
- **Input Validation**: Comprehensive parameter validation
- **Error Handling**: Graceful fallbacks and user guidance

---

## 🛠️ **Prerequisites**

### **System Requirements**
- **Python**: 3.7 or higher
- **OS**: macOS, Linux, or Windows
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 2GB free space

### **Required Security Tools**

#### **Core Tools (Required)**
```bash
# Nmap - Network scanning
brew install nmap          # macOS
sudo apt install nmap      # Ubuntu/Debian
sudo yum install nmap      # CentOS/RHEL

# Medusa - Brute force
brew install medusa        # macOS
sudo apt install medusa    # Ubuntu/Debian
sudo yum install medusa    # CentOS/RHEL
```

#### **Additional Tools (Optional)**
```bash
# Nikto - Web vulnerability scanning
brew install nikto         # macOS
sudo apt install nikto     # Ubuntu/Debian

# Hydra - Multi-protocol brute force
brew install hydra         # macOS
sudo apt install hydra     # Ubuntu/Debian

# Gobuster - Directory/file enumeration
brew install gobuster      # macOS
sudo apt install gobuster  # Ubuntu/Debian

# Tor - Network anonymization
brew install tor           # macOS
sudo apt install tor       # Ubuntu/Debian
```

---

## 🚀 **Installation & Setup**

### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/XKRed27-Security-Suite.git
cd XKRed27-Security-Suite
```

### **2. Create Virtual Environment**
```bash
python -m venv venv

# Activate on macOS/Linux
source venv/bin/activate

# Activate on Windows
venv\Scripts\activate
```

### **3. Install Dependencies**
```bash
pip install -r requirements.txt
```

### **4. Verify Installation**
```bash
# Check Python version
python --version

# Check Streamlit
streamlit --version

# Check security tools
nmap --version
medusa -v
```

---

## 🎯 **Usage**

### **Starting the Application**
```bash
# Basic startup
streamlit run main.py

# With custom port
streamlit run main.py --server.port 8501

# Headless mode (no browser auto-open)
streamlit run main.py --server.headless true
```

### **Access the Application**
- **Local**: http://localhost:8501
- **Network**: http://your-ip:8501
- **External**: http://your-external-ip:8501

---

## 🛡️ **Security Tools Overview**

### 🌐 **Network Discovery Scanner**
**Purpose**: Fast network enumeration and host discovery
- **Features**: Ping scanning, network mapping, host resolution
- **Use Cases**: Network reconnaissance, asset discovery, network mapping
- **Output**: Live host list, IP ranges, hostname resolution

### 🔍 **Nmap Network Scanner**
**Purpose**: Comprehensive network security auditing
- **Scan Types**: TCP SYN, Connect, UDP, ACK, Ping
- **Advanced Features**: OS detection, service enumeration, NSE scripts
- **Timing**: 6 timing templates from Paranoid to Insane
- **Ports**: Default, all ports, custom ranges

### 🔓 **Medusa Brute Force**
**Purpose**: Multi-protocol authentication testing
- **Protocols**: SSH, FTP, HTTP, Telnet, MySQL, PostgreSQL
- **Authentication**: Single credentials, lists, or file uploads
- **Performance**: Configurable threading, real-time monitoring
- **Output**: Successful logins, detailed reporting

### 🔍 **Nikto Web Scanner**
**Purpose**: Web server vulnerability assessment
- **Checks**: 6700+ potentially dangerous files/programs
- **Features**: SSL support, custom tuning, multiple outputs
- **Profiles**: 9 scan tuning profiles for different scenarios
- **Reporting**: HTML, XML, CSV, and custom formats

### 🔒 **Hydra Multi-Protocol**
**Purpose**: High-speed network login cracking
- **Protocols**: 22+ protocols including SSH, FTP, HTTP, SMB
- **Performance**: Parallel processing, optimized for speed
- **Features**: Custom wordlists, timing control, stealth options
- **Output**: Successful credentials, attack statistics

### 🔍 **Gobuster Multi-Mode Scanner**
**Purpose**: Directory, file, and service enumeration
- **Modes**: Directory, DNS, VHOST, Fuzz, S3 bucket discovery
- **Features**: High-performance concurrent processing
- **Wordlists**: Built-in lists, custom uploads, manual input
- **Output**: Discovered items, IP addresses, detailed results

### 🕵️ **AnonSurf Network Anonymizer**
**Purpose**: Network privacy and operational security
- **Methods**: Tor routing, VPN integration, proxy chains
- **Features**: DNS leak protection, IP anonymization
- **Integration**: Works with all security tools
- **Status**: Real-time connection monitoring

---

## 📊 **Advanced Features**

### **Real-time Monitoring**
- **System Performance**: CPU, memory, network I/O monitoring
- **Progress Tracking**: Live updates during operations
- **Resource Optimization**: Automatic thread count recommendations

### **Professional Reporting**
- **HTML Reports**: Beautiful, styled reports with tables
- **JSON Export**: Structured data for integration
- **Raw Output**: Original tool output preservation
- **Download Options**: Multiple format support

### **Input Validation**
- **Parameter Checking**: Comprehensive input validation
- **Error Handling**: Graceful fallbacks and user guidance
- **Security Warnings**: Clear usage guidelines and best practices

---

## ⚠️ **Legal and Ethical Considerations**

### **IMPORTANT DISCLAIMER**
This tool is designed for **legitimate security testing and educational purposes only**.

### **Legal Usage Guidelines**
✅ **Authorized Testing**: Only scan networks you own or have explicit permission to test  
✅ **Educational Purpose**: Learning network security concepts and tools  
✅ **Security Auditing**: Authorized penetration testing and security assessments  
✅ **Compliance Testing**: Meeting regulatory and industry security requirements  

❌ **Unauthorized Scanning**: Never scan networks without permission  
❌ **Malicious Intent**: Do not use for illegal activities or attacks  
❌ **Network Disruption**: Avoid overwhelming target systems  

### **Best Practices**
1. **Always obtain written authorization** before scanning external networks
2. **Respect rate limits** and avoid overwhelming target systems
3. **Document your testing activities** for compliance and reporting
4. **Follow your organization's security testing policies**
5. **Be mindful of network impact** during scans
6. **Use appropriate timing** to avoid detection

---

## 🔧 **Troubleshooting**

### **Common Issues**

#### **"Command not found" Errors**
```bash
# Verify tool installation
which nmap
which medusa
which nikto

# Check PATH
echo $PATH
```

#### **Permission Denied Errors**
```bash
# Some scans require elevated privileges
sudo streamlit run main.py

# Or use built-in sudo authentication in the app
```

#### **Port Already in Use**
```bash
# Use different port
streamlit run main.py --server.port 8502

# Or kill existing process
pkill -f streamlit
```

#### **Performance Issues**
- **Reduce thread count** in tool settings
- **Use appropriate timing** templates
- **Limit port ranges** for faster scans
- **Check system resources** with built-in monitoring

### **Getting Help**
- **Documentation**: Check tool-specific documentation
- **Issues**: Report bugs on GitHub
- **Community**: Join security testing communities
- **Support**: Check troubleshooting guides

---

## 🚀 **Development & Contributing**

### **Development Setup**
```bash
# Clone repository
git clone https://github.com/yourusername/XKRed27-Security-Suite.git
cd XKRed27-Security-Suite

# Create virtual environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest

# Start development server
streamlit run main.py
```

### **Contributing Guidelines**
1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** with proper testing
4. **Commit your changes**: `git commit -m 'Add amazing feature'`
5. **Push to the branch**: `git push origin feature/amazing-feature`
6. **Open a Pull Request**

### **Code Style**
- **Python**: Follow PEP 8 guidelines
- **HTML/CSS**: Use consistent formatting
- **Documentation**: Update README and docstrings
- **Testing**: Include tests for new features

---

## 📁 **Project Structure**

```
XKRed27-Security-Suite/
├── main.py                 # Main application entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── tools/                 # Security tool modules
│   ├── __init__.py
│   ├── network_scanner.py     # Network discovery
│   ├── nmap_scanner.py        # Nmap integration
│   ├── medusa_brute.py        # Medusa brute force
│   ├── nikto_scanner.py       # Nikto web scanning
│   ├── hydra_scanner.py       # Hydra multi-protocol
│   ├── gobuster_scanner.py    # Gobuster enumeration
│   ├── anon_surfer.py         # Network anonymization
│   └── system_monitor.py      # Performance monitoring
├── data/                  # Data storage
├── venv/                  # Virtual environment
└── docs/                  # Documentation
```

---

## 📊 **Screenshots**

<div align="center">

### 🏠 **Modern Landing Page**
![Landing Page](docs/screenshots/landing-page.png)

### 🔍 **Nmap Scanner Interface**
![Nmap Interface](docs/screenshots/nmap-interface.png)

### 🔓 **Medusa Brute Force**
![Medusa Interface](docs/screenshots/medusa-interface.png)

### 📊 **Professional Reports**
![HTML Report](docs/screenshots/html-report.png)

</div>

---

## 📈 **Performance & Scalability**

### **System Requirements**
- **Minimum**: 4GB RAM, 2-core CPU
- **Recommended**: 8GB RAM, 4-core CPU
- **Optimal**: 16GB RAM, 8-core CPU

### **Performance Features**
- **Real-time Monitoring**: CPU, memory, network I/O tracking
- **Thread Optimization**: Automatic thread count recommendations
- **Resource Management**: Efficient memory and CPU usage
- **Progress Tracking**: Live updates during operations

### **Scalability**
- **Multi-threading**: Configurable thread counts for all tools
- **Batch Processing**: Handle multiple targets efficiently
- **Memory Management**: Optimized for large datasets
- **Network Optimization**: Efficient network utilization

---

## 🔒 **Security Features**

### **Authentication & Authorization**
- **Built-in Sudo Support**: Secure privilege escalation
- **Password Protection**: Secure credential input
- **Session Management**: Secure session handling
- **Access Control**: Tool-specific permissions

### **Data Protection**
- **Local Storage**: All data stays on your machine
- **Memory Protection**: Credentials cleared after use
- **Secure Communication**: Local tool execution
- **Audit Logging**: Operation tracking and logging

### **Privacy Features**
- **Network Anonymization**: Tor and VPN integration
- **DNS Protection**: Leak prevention
- **Traffic Masking**: Operational security
- **Identity Protection**: Anonymous operations

---

## 📚 **Documentation & Resources**

### **Tool Documentation**
- **Nmap**: [nmap.org/book](https://nmap.org/book/)
- **Medusa**: [foofus.net/medusa](https://foofus.net/medusa/)
- **Nikto**: [cirt.net/Nikto2](https://cirt.net/Nikto2)
- **Hydra**: [github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra)
- **Gobuster**: [github.com/OJ/gobuster](https://github.com/OJ/gobuster)

### **Learning Resources**
- **Network Security**: [SANS Network Security](https://www.sans.org/cyber-security-courses/network-security/)
- **Penetration Testing**: [Offensive Security](https://www.offensive-security.com/)
- **Web Security**: [OWASP](https://owasp.org/)
- **Security Tools**: [Kali Linux Tools](https://tools.kali.org/)

---

## 🤝 **Support & Community**

### **Getting Help**
- **GitHub Issues**: Report bugs and request features
- **Discussions**: Join community discussions
- **Documentation**: Comprehensive guides and tutorials
- **Examples**: Sample configurations and use cases

### **Community Guidelines**
- **Be Respectful**: Treat others with respect and professionalism
- **Share Knowledge**: Help others learn and grow
- **Follow Guidelines**: Adhere to project and community standards
- **Report Issues**: Help improve the project with bug reports

---

## 📄 **License**

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### **License Summary**
- **Commercial Use**: ✅ Allowed
- **Modification**: ✅ Allowed
- **Distribution**: ✅ Allowed
- **Private Use**: ✅ Allowed
- **Liability**: ❌ No warranty provided

---

## 🙏 **Acknowledgments**

### **Open Source Projects**
- **[Nmap](https://nmap.org/)** - The amazing network scanning tool
- **[Streamlit](https://streamlit.io/)** - The fantastic web app framework
- **[shadcn/ui](https://ui.shadcn.com/)** - Beautiful UI components
- **[Security Tools](https://tools.kali.org/)** - The security community

### **Contributors**
- **Security Researchers**: For continuous feedback and testing
- **Open Source Community**: For inspiration and collaboration
- **Users**: For bug reports and feature requests

---

## 📞 **Contact & Links**

- **GitHub**: [github.com/yourusername/XKRed27-Security-Suite](https://github.com/yourusername/XKRed27-Security-Suite)
- **Issues**: [GitHub Issues](https://github.com/yourusername/XKRed27-Security-Suite/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/XKRed27-Security-Suite/discussions)
- **Wiki**: [Project Wiki](https://github.com/yourusername/XKRed27-Security-Suite/wiki)

---

<div align="center">

**⭐ Star this repository if you find it useful! ⭐**

**🛡️ Built with ❤️ for the security community 🛡️**

</div>

---

**⚠️ Disclaimer**: The authors and contributors of this project are not responsible for any misuse of this tool. Users are solely responsible for ensuring their use complies with applicable laws and regulations. This tool is designed for legitimate security testing and educational purposes only.
