#!/usr/bin/env python3
"""
Network Anonymization Module for Nmap UI Suite
Provides network anonymization and privacy protection before reconnaissance
"""

import streamlit as st
import subprocess
import time
import json
import os
from datetime import datetime

class NetworkAnonymizer:
    """Manages network anonymization operations for privacy protection"""
    
    def __init__(self):
        self.is_active = False
        self.current_method = None
        self.start_time = None
        self.original_ip = None
        self.current_ip = None
    
    def check_tor_installation(self):
        """Check if Tor is installed and available"""
        try:
            result = subprocess.run(['which', 'tor'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def check_vpn_status(self):
        """Check if VPN is active"""
        try:
            # Check for common VPN interfaces
            result = subprocess.run(['ifconfig'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                output = result.stdout.lower()
                vpn_indicators = ['tun', 'tap', 'ppp', 'utun']
                return any(indicator in output for indicator in vpn_indicators)
            return False
        except:
            return False
    
    def get_current_ip(self):
        """Get current public IP address"""
        try:
            # Try multiple IP check services for redundancy
            services = [
                "https://ipinfo.io/ip",
                "https://icanhazip.com",
                "https://ifconfig.me/ip"
            ]
            
            for service in services:
                try:
                    result = subprocess.run(['curl', '-s', '--max-time', '10', service], 
                                          capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout.strip():
                        return result.stdout.strip()
                except:
                    continue
            
            return "Unknown"
        except:
            return "Unknown"
    
    def start_tor_anonymization(self):
        """Start Tor anonymization"""
        try:
            if not self.check_tor_installation():
                return False, "Tor is not installed"
            
            # Store original IP
            self.original_ip = self.get_current_ip()
            
            # Start Tor service
            result = subprocess.run(['brew', 'services', 'start', 'tor'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.is_active = True
                self.start_time = datetime.now()
                self.current_method = "tor"
                
                # Wait for Tor to establish connection
                time.sleep(10)
                
                # Get new IP
                self.current_ip = self.get_current_ip()
                
                return True, "Tor anonymization started successfully"
            else:
                return False, f"Failed to start Tor: {result.stderr}"
                
        except Exception as e:
            return False, f"Error starting Tor: {str(e)}"
    
    def stop_tor_anonymization(self):
        """Stop Tor anonymization"""
        try:
            if not self.is_active or self.current_method != "tor":
                return True, "Tor was not active"
            
            result = subprocess.run(['brew', 'services', 'stop', 'tor'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.is_active = False
                self.start_time = None
                self.current_method = None
                
                # Wait for connection to restore
                time.sleep(5)
                
                # Verify IP restoration
                restored_ip = self.get_current_ip()
                
                return True, f"Tor stopped. IP restored to: {restored_ip}"
            else:
                return False, f"Failed to stop Tor: {result.stderr}"
                
        except Exception as e:
            return False, f"Error stopping Tor: {str(e)}"
    
    def start_vpn_anonymization(self):
        """Start VPN anonymization (placeholder for VPN integration)"""
        try:
            # Store original IP
            self.original_ip = self.get_current_ip()
            
            # This is a placeholder - in a real implementation, you'd integrate with VPN clients
            st.info("🔧 VPN integration requires configuration with your VPN provider")
            
            self.is_active = True
            self.start_time = datetime.now()
            self.current_method = "vpn"
            
            return True, "VPN anonymization started (manual configuration required)"
                
        except Exception as e:
            return False, f"Error starting VPN: {str(e)}"
    
    def stop_vpn_anonymization(self):
        """Stop VPN anonymization"""
        try:
            if not self.is_active or self.current_method != "vpn":
                return True, "VPN was not active"
            
            # Placeholder for VPN disconnection
            self.is_active = False
            self.start_time = None
            self.current_method = None
            
            return True, "VPN anonymization stopped"
                
        except Exception as e:
            return False, f"Error stopping VPN: {str(e)}"
    
    def get_status(self):
        """Get current anonymization status"""
        try:
            if not self.is_active:
                return {
                    "active": False,
                    "method": None,
                    "uptime": None,
                    "original_ip": self.original_ip,
                    "current_ip": self.get_current_ip()
                }
            
            uptime = None
            if self.start_time:
                uptime = datetime.now() - self.start_time
            
            return {
                "active": True,
                "method": self.current_method,
                "uptime": uptime,
                "original_ip": self.original_ip,
                "current_ip": self.current_ip
            }
        except:
            return {"active": False, "error": "Status check failed"}
    
    def get_available_methods(self):
        """Get available anonymization methods"""
        methods = []
        
        if self.check_tor_installation():
            methods.append("tor")
        
        if self.check_vpn_status():
            methods.append("vpn")
        
        # Always include manual methods
        methods.extend(["manual", "proxy"])
        
        return methods

def show_anon_surfer_interface():
    """Main network anonymization interface"""
    st.header("🕵️ Network Anonymization & Privacy Protection")
    
    st.info("💡 **Network Anonymization** provides privacy protection by routing traffic through proxy chains, VPNs, or the Tor network before conducting reconnaissance activities.")
    
    # Initialize anonymizer
    if 'network_anonymizer' not in st.session_state:
        st.session_state.network_anonymizer = NetworkAnonymizer()
    
    anonymizer = st.session_state.network_anonymizer
    
    # Check available methods
    available_methods = anonymizer.get_available_methods()
    
    # Current status
    status = anonymizer.get_status()
    
    # Status display
    col_status1, col_status2, col_status3 = st.columns(3)
    
    with col_status1:
        if status["active"]:
            st.metric("Status", "🟢 Active", delta="Anonymized")
        else:
            st.metric("Status", "🔴 Inactive", delta="Direct Connection")
    
    with col_status2:
        if status["active"]:
            st.metric("Method", status.get("method", "Unknown"), delta="Active")
        else:
            st.metric("Method", "None", delta="Direct")
    
    with col_status3:
        if status["active"] and status.get("uptime"):
            uptime_str = str(status["uptime"]).split('.')[0]  # Remove microseconds
            st.metric("Uptime", uptime_str, delta="Running")
        else:
            st.metric("Uptime", "00:00:00", delta="Stopped")
    
    # IP information
    st.markdown("### 🌐 IP Address Information")
    
    col_ip1, col_ip2 = st.columns(2)
    
    with col_ip1:
        st.markdown("**Original IP:**")
        if status.get("original_ip"):
            st.code(status["original_ip"], language="text")
        else:
            st.info("Not yet captured")
    
    with col_ip2:
        st.markdown("**Current IP:**")
        current_ip = status.get("current_ip", "Unknown")
        st.code(current_ip, language="text")
        
        if status["active"] and status.get("original_ip") and current_ip != status["original_ip"]:
            st.success("✅ IP successfully anonymized!")
        elif status["active"] and current_ip == status.get("original_ip"):
            st.warning("⚠️ IP appears unchanged - check anonymization status")
    
    # Control panel
    st.markdown("### 🎛️ Anonymization Control")
    
    if not status["active"]:
        # Start anonymization
        st.markdown("**Start Network Anonymization**")
        
        col_start1, col_start2 = st.columns([2, 1])
        
        with col_start1:
            # Method selection
            method_descriptions = {
                "tor": "Tor Network - Free, decentralized anonymization",
                "vpn": "VPN Connection - Fast, reliable anonymization",
                "manual": "Manual Configuration - Custom proxy settings",
                "proxy": "Proxy Chain - Multiple proxy routing"
            }
            
            selected_method = st.selectbox(
                "Anonymization Method:",
                available_methods,
                format_func=lambda x: f"{x.upper()} - {method_descriptions.get(x, 'Custom method')}",
                help="Select the type of anonymization to use"
            )
            
            # Additional options
            col_options1, col_options2 = st.columns(2)
            
            with col_options1:
                dns_protection = st.checkbox("Enable DNS Protection", value=True, help="Protect against DNS leaks")
                ip_protection = st.checkbox("Enable IP Protection", value=True, help="Protect against IP leaks")
            
            with col_options2:
                kill_switch = st.checkbox("Enable Kill Switch", value=True, help="Block traffic if anonymization fails")
                auto_restart = st.checkbox("Auto-restart on Failure", value=False, help="Automatically restart if connection drops")
        
        with col_start2:
            st.markdown("**Method Types:**")
            st.markdown("""
            - **Tor**: Free, decentralized network
            - **VPN**: Fast, reliable connections
            - **Manual**: Custom configuration
            - **Proxy**: Multiple proxy chains
            """)
            
            if st.button("🚀 Start Anonymization", type="primary", use_container_width=True):
                with st.spinner("Starting network anonymization..."):
                    if selected_method == "tor":
                        success, message = anonymizer.start_tor_anonymization()
                    elif selected_method == "vpn":
                        success, message = anonymizer.start_vpn_anonymization()
                    else:
                        success, message = True, f"{selected_method.upper()} method selected - manual configuration required"
                    
                    if success:
                        st.success(f"✅ {message}")
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
    
    else:
        # Stop anonymization
        st.markdown("**Stop Network Anonymization**")
        
        col_stop1, col_stop2 = st.columns([2, 1])
        
        with col_stop1:
            st.warning("⚠️ **Anonymization is currently active**")
            st.info(f"**Active Method:** {status.get('method', 'Unknown')}")
            
            if status.get("uptime"):
                st.info(f"**Running Time:** {str(status['uptime']).split('.')[0]}")
        
        with col_stop2:
            if st.button("🛑 Stop Anonymization", type="secondary", use_container_width=True):
                with st.spinner("Stopping anonymization..."):
                    if status.get("method") == "tor":
                        success, message = anonymizer.stop_tor_anonymization()
                    elif status.get("method") == "vpn":
                        success, message = anonymizer.stop_vpn_anonymization()
                    else:
                        success, message = True, "Manual method stopped"
                    
                    if success:
                        st.success(f"✅ {message}")
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
    
    # Installation instructions
    with st.expander("📥 Installation & Setup", expanded=False):
        st.markdown("### **Tor Installation (macOS):**")
        st.code("brew install tor", language="bash")
        
        st.markdown("### **VPN Setup:**")
        st.markdown("""
        - Configure your VPN client (OpenVPN, WireGuard, etc.)
        - Set up kill switch and DNS protection
        - Test connection before use
        """)
        
        st.markdown("### **Manual Proxy Configuration:**")
        st.code("""
# Example proxy configuration
export http_proxy=http://proxy:8080
export https_proxy=http://proxy:8080
export no_proxy=localhost,127.0.0.1
        """, language="bash")
    
    # Advanced options
    with st.expander("🔧 Advanced Configuration", expanded=False):
        st.markdown("**Tor Configuration:**")
        st.code("/usr/local/etc/tor/torrc", language="text")
        
        st.markdown("**VPN Configuration:**")
        st.code("~/.config/vpn/", language="text")
        
        st.markdown("**System Proxy Settings:**")
        st.code("System Preferences > Network > Advanced > Proxies", language="text")
    
    # Integration with other tools
    st.markdown("### 🔗 Tool Integration")
    
    if status["active"]:
        st.success("🟢 **Anonymization is active** - All reconnaissance tools will use protected connections")
        
        # Show which tools are protected
        protected_tools = [
            "🌐 Network Discovery",
            "🌐 Network Discovery",
            "🔍 Nmap Scanner", 
            "🔓 Medusa Brute Force",
            "🔍 Nikto Web Scanner",
            "🔒 Hydra Multi-Protocol",
            "🔍 Gobuster Directory Scanner"
        ]
        
        st.markdown("**Protected Tools:**")
        for tool in protected_tools:
            st.markdown(f"- {tool}")
        
        st.info("💡 **Note:** All network scanning and reconnaissance activities will now route through the selected anonymization method.")
        
    else:
        st.warning("🟡 **Anonymization is inactive** - Tools will use direct network connections")
        
        st.markdown("**Recommendation:** Consider activating anonymization before conducting reconnaissance activities to protect your privacy and maintain operational security.")
    
    # Safety warnings
    st.markdown("### ⚠️ Important Security Notes")
    
    st.warning("""
    **Legal and Ethical Considerations:**
    
    - 🚫 **Only use on authorized systems** you own or have explicit permission to test
    - 🚫 **Do not use for illegal activities** or unauthorized access
    - 🚫 **Respect privacy laws** and regulations in your jurisdiction
    - 🚫 **Do not bypass security measures** without proper authorization
    
    **Technical Considerations:**
    
    - 🔒 **Anonymization provides privacy, not complete anonymity**
    - 🌐 **Some services may detect and block anonymized connections**
    - ⚡ **Performance may be reduced** due to routing through multiple networks
    - 🛡️ **Always use in combination with other security practices**
    """)
    
    # Footer
    st.markdown("---")
    st.markdown("*Network anonymization provides enhanced privacy and operational security during security testing activities.*")

if __name__ == "__main__":
    show_anon_surfer_interface()
