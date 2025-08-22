import streamlit as st
import subprocess
import json
import xml.etree.ElementTree as ET
import pandas as pd
import time
import re
import os
import base64
from datetime import datetime
import threading
import queue
import getpass
from streamlit_shadcn_ui import button, input, textarea, select, switch, slider, card, tabs, badges, hover_card

# Page configuration
st.set_page_config(
    page_title="XKRed27 Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Theme is configured via .streamlit/config.toml

# Modern shadcn-inspired styling
st.markdown("""
<style>
/* Modern typography and spacing */
.main-header {
    font-size: 3.5rem;
    font-weight: 800;
    text-align: center;
    margin-bottom: 3rem;
    background: linear-gradient(135deg, #0f172a 0%, #475569 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: -0.025em;
}

/* Modern card design */
.tool-card {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 2rem;
    margin: 1.5rem 0;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
    transition: all 0.2s ease-in-out;
    position: relative;
    overflow: hidden;
}

.tool-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 25px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    border-color: #cbd5e1;
}

.tool-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 4px;
    background: linear-gradient(90deg, #3b82f6, #8b5cf6, #06b6d4);
}

.tool-title {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 1rem;
    color: #0f172a;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.tool-description {
    font-size: 1rem;
    margin-bottom: 1.5rem;
    color: #475569;
    line-height: 1.6;
}

.tool-features {
    color: #64748b;
    font-size: 0.9rem;
}

.tool-features ul {
    margin: 0.5rem 0;
    padding-left: 1.5rem;
}

.tool-features li {
    margin: 0.25rem 0;
}

/* Modern button styling */
.stButton > button {
    background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
    border: none;
    border-radius: 8px;
    color: white;
    font-weight: 600;
    padding: 0.75rem 1.5rem;
    transition: all 0.2s ease-in-out;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
}

.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
}

/* Modern sidebar styling */
.sidebar .sidebar-content {
    background: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);
}

/* Status indicators */
.status-active {
    background: #dcfce7;
    color: #166534;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
}

.status-inactive {
    background: #fef2f2;
    color: #dc2626;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
}

/* Modern container styling */
.modern-container {
    background: white;
    border-radius: 12px;
    padding: 2rem;
    margin: 1.5rem 0;
    border: 1px solid #e2e8f0;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
}

/* Gradient text */
.gradient-text {
    background: linear-gradient(135deg, #3b82f6, #8b5cf6, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-weight: 700;
}
</style>
""", unsafe_allow_html=True)

def show_landing_page():
    """Display the main landing page"""
    st.markdown('<h1 class="main-header">🛡️ XKRed27 Security Suite</h1>', unsafe_allow_html=True)
    
    # Hero section with modern styling
    st.markdown('<h2 class="gradient-text" style="font-size: 2.5rem; margin-bottom: 1rem;">🚀 Professional Network Security Tools</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    A comprehensive suite of network security and penetration testing tools with modern web interfaces. 
    Built for security professionals, penetration testers, and network administrators.
    """)
    
    # Feature highlights using columns
    col1, col2, col3 = st.columns(3)
    
    with col1:
        with st.container():
            st.markdown("""
            <div style="padding: 1.5rem; background: #f8fafc; border-radius: 8px; border-left: 4px solid #3b82f6; height: 100%;">
                <h3 style="color: #0f172a; margin-bottom: 0.5rem; font-size: 1.1rem;">🎨 Modern Web Interface</h3>
                <p style="color: #64748b; margin: 0; font-size: 0.9rem;">Clean, responsive UI for all tools</p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        with st.container():
            st.markdown("""
            <div style="padding: 1.5rem; background: #f8fafc; border-radius: 8px; border-left: 4px solid #8b5cf6; height: 100%;">
                <h3 style="color: #0f172a; margin-bottom: 0.5rem; font-size: 0.9rem;">🔐 Secure Authentication</h3>
                <p style="color: #64748b; margin: 0; font-size: 0.9rem;">Built-in sudo support for privileged operations</p>
            </div>
            """, unsafe_allow_html=True)
    
    with col3:
        with st.container():
            st.markdown("""
            <div style="padding: 1.5rem; background: #f8fafc; border-radius: 8px; border-left: 4px solid #06b6d4; height: 100%;">
                <h3 style="color: #0f172a; margin-bottom: 0.5rem; font-size: 1.1rem;">📊 Professional Reports</h3>
                <p style="color: #64748b; margin: 0; font-size: 0.9rem;">Export results in multiple formats</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Tool grid with modern cards
    st.markdown('<h2 class="gradient-text" style="text-align: center; margin: 3rem 0 2rem 0;">🔧 Available Security Tools</h2>', unsafe_allow_html=True)
    
    # First row - Network Discovery (full width)
    st.markdown("""
    <div class="tool-card">
        <div class="tool-title">🌐 Network Discovery Scanner</div>
        <div class="tool-description">
            Fast network discovery tool to identify live hosts on your network. 
            Automatically discovers available IP addresses and saves them for use 
            with other security tools in the suite.
        </div>
        <div class="tool-features">
            <strong>Features:</strong>
            <ul>
                <li>Automated network range detection</li>
                <li>Multi-threaded host discovery</li>
                <li>Hostname resolution and mapping</li>
                <li>Export results for other tools</li>
                <li>Integration with Nmap and Medusa scanners</li>
            </ul>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Second row - Nmap, Medusa, Nikto, and Hydra
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="tool-card">
            <div class="tool-title">🔍 Nmap Network Scanner</div>
            <div class="tool-description">
                Advanced network discovery and security auditing tool. Perform comprehensive 
                network reconnaissance with support for various scan types, OS detection, 
                service enumeration, and vulnerability assessment.
            </div>
            <div class="tool-features">
                <strong>Features:</strong>
                <ul>
                    <li>Multiple scan types (TCP SYN, Connect, UDP, etc.)</li>
                    <li>OS and service detection</li>
                    <li>Aggressive scanning with NSE scripts</li>
                    <li>Custom port ranges and timing</li>
                    <li>Professional HTML/JSON reports</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="tool-card">
            <div class="tool-title">🔓 Medusa Brute Force</div>
            <div class="tool-description">
                Fast, parallel, and modular login brute-forcer for network services. 
                Test password security across multiple protocols with flexible 
                input options and comprehensive reporting.
            </div>
            <div class="tool-features">
                <strong>Features:</strong>
                <ul>
                    <li>Multiple protocol support (SSH, FTP, HTTP, etc.)</li>
                    <li>Parallel brute-force attacks</li>
                    <li>Flexible wordlists and user lists</li>
                    <li>Real-time attack progress</li>
                    <li>Detailed success/failure reporting</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="tool-card">
            <div class="tool-title">🔍 Nikto Web Scanner</div>
            <div class="tool-description">
                Comprehensive web vulnerability scanner that tests web servers for 
                dangerous files, outdated software, and security misconfigurations. 
                Perform thorough web application security assessments.
            </div>
            <div class="tool-features">
                <strong>Features:</strong>
                <ul>
                    <li>6700+ potentially dangerous files/programs</li>
                    <li>Checks for outdated server versions</li>
                    <li>Server configuration issues detection</li>
                    <li>Multiple output formats (HTML, XML, CSV)</li>
                    <li>SSL/HTTPS support with custom ports</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="tool-card">
            <div class="tool-title">🔒 Hydra Multi-Protocol</div>
            <div class="tool-description">
                Fast and flexible network logon cracker supporting dozens of protocols.
                Perform comprehensive brute force attacks against network services with
                advanced threading and authentication options.
            </div>
            <div class="tool-features">
                <strong>Features:</strong>
                <ul>
                    <li>22+ protocol support (SSH, FTP, HTTP, SMB, etc.)</li>
                    <li>High-performance parallel processing</li>
                    <li>Multiple authentication modes</li>
                    <li>Protocol-specific optimizations</li>
                    <li>Advanced timing and stealth options</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Third row - Gobuster and AnonSurf
    col_center = st.columns([1, 2, 1])
    with col_center[1]:
        st.markdown("""
        <div class="tool-card">
            <div class="tool-title">🔍 Gobuster Multi-Mode Scanner</div>
            <div class="tool-description">
                Fast multi-mode enumeration tool written in Go. Discover hidden 
                directories, files, subdomains, virtual hosts, fuzz parameters, 
                and AWS S3 buckets with high-performance parallel processing.
            </div>
            <div class="tool-features">
                <strong>Features:</strong>
                <ul>
                    <li>Directory & file enumeration (dir)</li>
                    <li>DNS subdomain discovery (dns)</li>
                    <li>Virtual host enumeration (vhost)</li>
                    <li>Parameter fuzzing (fuzz)</li>
                    <li>AWS S3 bucket discovery (s3)</li>
                    <li>High-performance concurrent processing</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Fourth row - AnonSurf (centered)
    col_center2 = st.columns([1, 2, 1])
    with col_center2[1]:
        st.markdown("""
        <div class="tool-card">
            <div class="tool-title">🕵️ AnonSurf Network Anonymizer</div>
            <div class="tool-description">
                Advanced network anonymization and privacy protection system. 
                Route all reconnaissance traffic through multiple proxy chains 
                including Tor, I2P, and VPN networks for enhanced operational security.
            </div>
            <div class="tool-features">
                <strong>Features:</strong>
                <ul>
                    <li>Multi-chain routing (Tor, I2P, VPN)</li>
                    <li>DNS leak protection</li>
                    <li>IP leak prevention</li>
                    <li>Traffic anonymization</li>
                    <li>Privacy enhancement</li>
                    <li>Tool integration</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Coming soon tools
    st.subheader("🚧 Coming Soon")
    
    coming_soon_tools = [
        ("📡 Aircrack-ng", "Wireless security auditing"),
        ("🔍 Dirb", "Web content discovery"),
        ("🛡️ SQLmap", "SQL injection testing"),
        ("🌐 Burp Suite", "Web application security"),
        ("📊 Metasploit", "Penetration testing framework"),
        ("🔐 John the Ripper", "Password cracking"),
        ("🕸️ Gobuster", "Directory/file brute-forcer"),
        ("🔎 Masscan", "High-speed port scanner")
    ]
    
    # Display coming soon tools in a grid
    cols = st.columns(4)
    for i, (tool_name, tool_desc) in enumerate(coming_soon_tools):
        with cols[i % 4]:
            st.markdown(f"""
            <div class="tool-card coming-soon">
                <div class="tool-title">{tool_name}</div>
                <div class="tool-description">{tool_desc}</div>
                <em>Coming Soon...</em>
            </div>
            """, unsafe_allow_html=True)
    
    # Instructions
    st.markdown("### 🎯 Getting Started")
    st.markdown("""
    Select a tool from the sidebar to begin your security assessment:
    
    1. **Network Discovery** - Start by discovering live hosts on your network
    2. **Nmap Scanner** - Perform detailed port scanning and service enumeration  
    3. **Medusa Brute Force** - Test authentication security on discovered services
    4. **Nikto Web Scanner** - Scan web applications for vulnerabilities and misconfigurations
    5. **Hydra Multi-Protocol** - Advanced brute force attacks across 22+ protocols
    6. **Gobuster Multi-Mode Scanner** - Discover directories, files, subdomains, virtual hosts, fuzz parameters, and AWS S3 buckets
    7. **AnonSurf Network Anonymizer** - Protect your privacy with network anonymization before reconnaissance
    8. **Additional Tools** - More tools will be added to expand your security toolkit
    
    **💡 Pro Tip:** Use Network Discovery first to find targets, then use the discovered 
    IP addresses across all scanners for comprehensive security assessment!
    
    **⚠️ Legal Notice:** These tools are for authorized security testing only. 
    Ensure you have proper authorization before testing any network or system.
    """)

# Import tool modules
from tools import network_scanner, nmap_scanner, medusa_brute, nikto_scanner, hydra_scanner, gobuster_scanner, anon_surfer

def show_navigation_sidebar():
    """Show consistent navigation sidebar for all pages with clickable navigation"""
    # Modern header with gradient text
    st.sidebar.markdown("""
    <div style="text-align: center; padding: 1.5rem 0;">
        <h1 style="font-size: 1.75rem; font-weight: 800; margin: 0; background: linear-gradient(135deg, #0f172a, #475569); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">🛡️ XKRed27</h1>
        <p style="font-size: 1rem; color: #64748b; margin: 0.5rem 0 0 0; font-weight: 600;">Security Suite</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    
    # Show current active tool with modern badge
    current_tool = {
        "home": "🏠 Home",
        "network": "🌐 Network Discovery", 
        "nmap": "🔍 Nmap Scanner",
        "medusa": "🔓 Medusa Brute Force",
        "nikto": "🔍 Nikto Web Scanner",
        "hydra": "🔒 Hydra Multi-Protocol",
        "gobuster": "🔍 Gobuster Directory Scanner",
        "anonsurf": "🕵️ AnonSurf Network Anonymizer"
    }.get(st.session_state.active_tab, "🏠 Home")
    
    st.sidebar.markdown(f"""
    <div style="padding: 0.75rem; background: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0; margin-bottom: 1.5rem;">
        <p style="margin: 0; font-size: 0.875rem; color: #64748b;">Currently Active</p>
        <p style="margin: 0.25rem 0 0 0; font-weight: 600; color: #0f172a;">{current_tool}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Navigation buttons with modern styling
    nav_items = [
        ("🏠", "Home", "home"),
        ("🌐", "Network Discovery", "network"),
        ("🔍", "Nmap Scanner", "nmap"),
        ("🔓", "Medusa Brute Force", "medusa"),
        ("🔍", "Nikto Web Scanner", "nikto"),
        ("🔒", "Hydra Multi-Protocol", "hydra"),
        ("🔍", "Gobuster Directory Scanner", "gobuster"),
        ("🕵️", "AnonSurf Network Anonymizer", "anonsurf")
    ]
    
    for icon, label, tab in nav_items:
        is_active = st.session_state.active_tab == tab
        if st.sidebar.button(f"{icon} {label}", key=f"nav_{tab}_btn", use_container_width=True, 
                           type="primary" if is_active else "secondary"):
            st.session_state.active_tab = tab
            st.rerun()
    
    st.sidebar.markdown("---")
    
    # Coming soon section with modern styling
    st.sidebar.markdown("""
    <div style="padding: 1rem; background: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0;">
        <h3 style="margin: 0 0 1rem 0; font-size: 1rem; color: #0f172a;">🚧 Coming Soon</h3>
        <div style="font-size: 0.875rem; color: #64748b; line-height: 1.6;">
            <p style="margin: 0.25rem 0;">📡 Aircrack-ng - Wireless security</p>
            <p style="margin: 0.25rem 0;">🔍 Dirb - Web content discovery</p>
            <p style="margin: 0.25rem 0;">🛡️ SQLmap - SQL injection testing</p>
            <p style="margin: 0.25rem 0;">🌐 Burp Suite - Web app security</p>
            <p style="margin: 0.25rem 0;">📊 Metasploit - Penetration testing</p>
            <p style="margin: 0.25rem 0;">🔐 John the Ripper - Password cracking</p>
            <p style="margin: 0.25rem 0;">🔎 Masscan - High-speed port scanner</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    
    # Help tip with modern styling
    st.sidebar.markdown("""
    <div style="padding: 1rem; background: #eff6ff; border-radius: 8px; border: 1px solid #dbeafe;">
        <p style="margin: 0; font-size: 0.875rem; color: #1e40af; font-weight: 500;">💡 Click any tool above to access its interface</p>
    </div>
    """, unsafe_allow_html=True)

def main():
    """Main application with conditional navigation"""
    
    # Initialize session state for active tab
    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = "home"
    
    # Show consistent navigation sidebar for all tabs
    show_navigation_sidebar()
    
    # Display content based on active tab
    if st.session_state.active_tab == "home":
        show_landing_page()
    elif st.session_state.active_tab == "network":
        network_scanner.network_scanner_app()
    elif st.session_state.active_tab == "nmap":
        nmap_scanner.show_nmap_interface()
    elif st.session_state.active_tab == "medusa":
        medusa_brute.show_medusa_interface()
    elif st.session_state.active_tab == "nikto":
        nikto_scanner.show_nikto_interface()
    elif st.session_state.active_tab == "hydra":
        hydra_scanner.show_hydra_interface()
    elif st.session_state.active_tab == "gobuster":
        gobuster_scanner.show_gobuster_interface()
    elif st.session_state.active_tab == "anonsurf":
        anon_surfer.show_anon_surfer_interface()
    else:
        # Fallback to home if invalid tab
        st.session_state.active_tab = "home"
        show_landing_page()

if __name__ == "__main__":
    main()
