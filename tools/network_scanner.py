"""
Network Discovery Scanner for XKRed27 Security Suite
Discovers live hosts on the network and saves results for use by other tools.
"""

import streamlit as st
import subprocess
import ipaddress
import socket
import threading
import time
from datetime import datetime
import json
import os

def get_local_network():
    """Get the local network range"""
    try:
        # Get local IP address
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Create network object (assuming /24)
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network.network_address) + "/24"
    except:
        return "192.168.1.0/24"

def ping_host(ip, results, progress_container):
    """Ping a single host and update results"""
    try:
        # Use ping command (works on macOS/Linux)
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1000', str(ip)], 
            capture_output=True, 
            text=True, 
            timeout=2
        )
        
        if result.returncode == 0:
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
            except:
                hostname = "Unknown"
            
            results.append({
                'ip': str(ip),
                'hostname': hostname,
                'status': 'up',
                'discovered_at': datetime.now().isoformat()
            })
            
            # Update progress
            with progress_container:
                st.success(f"✅ Found: {ip} ({hostname})")
                
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

def save_discovered_hosts(hosts):
    """Save discovered hosts to a JSON file for other tools"""
    try:
        os.makedirs('data', exist_ok=True)
        with open('data/discovered_hosts.json', 'w') as f:
            json.dump(hosts, f, indent=2)
        return True
    except Exception as e:
        st.error(f"Error saving hosts: {e}")
        return False

def load_discovered_hosts():
    """Load previously discovered hosts"""
    try:
        if os.path.exists('data/discovered_hosts.json'):
            with open('data/discovered_hosts.json', 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def network_scanner_app():
    """Main Network Scanner Application"""
    
    st.header("🌐 Network Discovery Scanner")
    st.markdown("Discover live hosts on your network and save them for use with Nmap and Medusa.")
    
    # Configuration section
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📡 Scan Configuration")
        
        # Auto-detect local network
        default_network = get_local_network()
        network_range = st.text_input(
            "Network Range (CIDR)",
            value=default_network,
            key="network_range_input",
            help="Enter the network range to scan (e.g., 192.168.1.0/24)"
        )
        
        # Scan options
        max_threads = st.slider("Concurrent Threads", 1, 50, 20, key="max_threads_slider", help="Number of simultaneous pings")
        timeout = st.slider("Timeout (seconds)", 1, 5, 2, key="timeout_slider", help="Ping timeout per host")
        
    with col2:
        st.subheader("🎯 Quick Targets")
        
        # Common network ranges
        if st.button("🏠 Home Network (192.168.1.0/24)", key="home_network_btn"):
            st.session_state['network_range'] = "192.168.1.0/24"
            st.rerun()
            
        if st.button("🏢 Office Network (192.168.0.0/24)", key="office_network_btn"):
            st.session_state['network_range'] = "192.168.0.0/24"
            st.rerun()
            
        if st.button("🔧 Lab Network (10.0.0.0/24)", key="lab_network_btn"):
            st.session_state['network_range'] = "10.0.0.0/24"
            st.rerun()
    
    # Update network range from session state
    if 'network_range' in st.session_state:
        network_range = st.session_state['network_range']
        del st.session_state['network_range']
    
    # Scan button
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        scan_button = st.button("🚀 Start Network Scan", type="primary", key="start_scan_btn", use_container_width=True)
    
    # Display previous results
    previous_hosts = load_discovered_hosts()
    if previous_hosts:
        st.subheader("📋 Previously Discovered Hosts")
        
        # Create a more compact display
        host_data = []
        for host in previous_hosts:
            host_data.append({
                'IP Address': host['ip'],
                'Hostname': host['hostname'],
                'Status': '🟢 Up' if host['status'] == 'up' else '🔴 Down',
                'Last Seen': host['discovered_at'][:19].replace('T', ' ')
            })
        
        if host_data:
            st.dataframe(host_data, use_container_width=True)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🗑️ Clear Previous Results", key="clear_results_btn"):
                    try:
                        os.remove('data/discovered_hosts.json')
                        st.success("Previous results cleared!")
                        st.rerun()
                    except:
                        pass
                        
            with col2:
                # Export button
                if st.button("📥 Export Results", key="export_results_btn"):
                    csv_data = "IP Address,Hostname,Status,Last Seen\n"
                    for host in host_data:
                        csv_data += f"{host['IP Address']},{host['Hostname']},{host['Status'].replace('🟢 ', '').replace('🔴 ', '')},{host['Last Seen']}\n"
                    
                    st.download_button(
                        "📄 Download CSV",
                        csv_data,
                        "discovered_hosts.csv",
                        "text/csv"
                    )
    
    # Perform scan
    if scan_button:
        try:
            # Validate network range
            network = ipaddress.IPv4Network(network_range, strict=False)
            total_hosts = network.num_addresses - 2  # Exclude network and broadcast
            
            if total_hosts > 1000:
                st.error("⚠️ Network range too large! Please use a smaller range (max /22).")
                return
                
            st.success(f"🎯 Scanning {network_range} ({total_hosts} hosts)")
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            progress_container = st.container()
            
            # Results storage
            results = []
            threads = []
            completed = 0
            
            # Start scanning
            start_time = time.time()
            
            for ip in network.hosts():
                # Wait if too many threads
                while len([t for t in threads if t.is_alive()]) >= max_threads:
                    time.sleep(0.1)
                    
                    # Update progress
                    alive_threads = len([t for t in threads if t.is_alive()])
                    completed = len(threads) - alive_threads
                    progress = completed / total_hosts
                    progress_bar.progress(progress)
                    status_text.text(f"Scanning... {completed}/{total_hosts} hosts checked ({alive_threads} active threads)")
                
                # Start new thread
                thread = threading.Thread(
                    target=ping_host, 
                    args=(ip, results, progress_container)
                )
                thread.start()
                threads.append(thread)
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            # Final update
            progress_bar.progress(1.0)
            elapsed_time = time.time() - start_time
            
            # Display results
            if results:
                st.success(f"🎉 Scan Complete! Found {len(results)} live hosts in {elapsed_time:.1f} seconds")
                
                # Save results
                if save_discovered_hosts(results):
                    st.info("💾 Results saved for use with Nmap and Medusa scanners")
                
                # Display discovered hosts
                st.subheader("🖥️ Discovered Hosts")
                
                for host in sorted(results, key=lambda x: ipaddress.IPv4Address(x['ip'])):
                    col1, col2, col3 = st.columns([2, 3, 1])
                    with col1:
                        st.code(host['ip'])
                    with col2:
                        st.text(host['hostname'])
                    with col3:
                        st.success("🟢 Up")
                
            else:
                st.warning("🔍 No live hosts found in the specified range.")
                
        except ValueError as e:
            st.error(f"❌ Invalid network range: {e}")
        except Exception as e:
            st.error(f"❌ Scan failed: {e}")

def get_discovered_hosts_for_dropdown():
    """Get discovered hosts formatted for dropdown selection"""
    hosts = load_discovered_hosts()
    if not hosts:
        return []
    
    options = []
    for host in sorted(hosts, key=lambda x: ipaddress.IPv4Address(x['ip'])):
        if host['hostname'] != 'Unknown':
            options.append(f"{host['ip']} ({host['hostname']})")
        else:
            options.append(host['ip'])
    
    return options

def extract_ip_from_selection(selection):
    """Extract IP address from dropdown selection"""
    if not selection:
        return ""
    
    # Extract IP from "IP (hostname)" format
    if " (" in selection:
        return selection.split(" (")[0]
    else:
        return selection
