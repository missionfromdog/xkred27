#!/usr/bin/env python3
"""
Gobuster Directory/File Brute-Forcer Module for Nmap UI Suite
Provides comprehensive directory and file discovery capabilities
"""

import streamlit as st
import subprocess
import json
import pandas as pd
import time
import re
import os
from datetime import datetime
from tools.network_scanner import get_discovered_hosts_for_dropdown, extract_ip_from_selection
from tools.system_monitor import get_global_monitor, create_monitoring_dashboard, get_optimal_thread_count

def validate_url(url):
    """Validate URL format"""
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return re.match(url_pattern, url) is not None

def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def parse_gobuster_output(output, scan_mode):
    """Parse Gobuster output and structure it for display"""
    lines = output.split('\n')
    results = {
        'mode': scan_mode,
        'target': '',
        'wordlist_size': 0,
        'found_items': [],
        'status_codes': {},
        'scan_stats': {},
        'raw_output': output
    }
    
    for line in lines:
        line = line.strip()
        
        # Extract target URL
        if 'Target:' in line:
            results['target'] = line.split('Target:')[-1].strip()
        
        # Extract wordlist information
        if 'Wordlist:' in line or 'words' in line:
            try:
                # Look for word count in various formats
                word_match = re.search(r'(\d+)\s+words?', line)
                if word_match:
                    results['wordlist_size'] = int(word_match.group(1))
            except:
                pass
        
        # Parse found directories/files (different formats based on mode)
        if scan_mode == 'dir' and (line.startswith('/') or line.startswith('http')):
            # Directory mode: /admin (Status: 200) [Size: 1234]
            match = re.match(r'^(/[^\s]*)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?', line)
            if match:
                path, status, size = match.groups()
                item = {
                    'type': 'Directory/File',
                    'path': path,
                    'status_code': int(status),
                    'size': int(size) if size else 0,
                    'full_url': results.get('target', '') + path,
                    'raw_line': line
                }
                results['found_items'].append(item)
                
                # Count status codes
                status_code = int(status)
                results['status_codes'][status_code] = results['status_codes'].get(status_code, 0) + 1
        
        elif scan_mode == 'dns':
            # DNS subdomain enumeration
            # Format: subdomain.example.com IP1,IP2,IP3...
            # Skip separator lines and empty lines
            if line and not line.startswith('=') and not line.startswith('Gobuster') and not line.startswith('Starting') and not line.startswith('Finished'):
                # Check if line contains a domain and IP addresses
                if '.' in line and (' ' in line or '\t' in line):
                    parts = line.split()
                    if len(parts) >= 2:
                        subdomain = parts[0]
                        ips = parts[1:]
                        
                        # Validate it's a proper subdomain
                        if '.' in subdomain and not subdomain.startswith('http'):
                            item = {
                                'type': 'Subdomain',
                                'path': subdomain,
                                'status_code': 0,
                                'size': 0,
                                'full_url': f"http://{subdomain}",
                                'raw_line': line,
                                'ip_addresses': ips
                            }
                            results['found_items'].append(item)
        
        elif scan_mode == 'vhost' and (line.startswith('http') or '.' in line):
            # Virtual host enumeration
            match = re.match(r'^([^\s]+)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?', line)
            if match:
                vhost, status, size = match.groups()
                item = {
                    'type': 'Virtual Host',
                    'path': vhost,
                    'status_code': int(status),
                    'size': int(size) if size else 0,
                    'full_url': f"http://{vhost}",
                    'raw_line': line
                }
                results['found_items'].append(item)
                
                # Count status codes
                status_code = int(status)
                results['status_codes'][status_code] = results['status_codes'].get(status_code, 0) + 1
        
        elif scan_mode == 'fuzz' and line.startswith('http') and '=' in line:
            # Fuzzing mode results
            item = {
                'type': 'Fuzzed Parameter',
                'path': line,
                'status_code': 0,
                'size': 0,
                'full_url': line,
                'raw_line': line
            }
            results['found_items'].append(item)
        
        elif scan_mode == 's3' and line.startswith('http') and 's3.amazonaws.com' in line:
            # S3 bucket enumeration results
            item = {
                'type': 'S3 Bucket',
                'path': line,
                'status_code': 0,
                'size': 0,
                'full_url': line,
                'raw_line': line
            }
            results['found_items'].append(item)
        
        # Extract scan statistics
        if 'Requests/sec:' in line:
            try:
                rps_match = re.search(r'Requests/sec:\s*([\d.]+)', line)
                if rps_match:
                    results['scan_stats']['requests_per_second'] = float(rps_match.group(1))
            except:
                pass
        
        if 'Total time:' in line:
            try:
                time_match = re.search(r'Total time:\s*([\d.]+)', line)
                if time_match:
                    results['scan_stats']['total_time'] = float(time_match.group(1))
            except:
                pass
    
    return results

def run_gobuster_scan(command, progress_bar, status_text):
    """Run Gobuster scan with progress updates and monitoring"""
    try:
        # Get system monitor for performance tracking
        monitor = get_global_monitor()
        
        # Start the process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )
        
        output = ""
        error_output = ""
        found_count = 0
        last_monitor_update = time.time()
        
        status_text.text("Starting Gobuster directory/file brute-force scan...")
        progress_bar.progress(0.1)
        
        # Read output line by line
        while True:
            output_line = process.stdout.readline()
            if output_line == '' and process.poll() is not None:
                break
            if output_line:
                output += output_line
                line_lower = output_line.lower()
                
                # Update progress based on found items
                if output_line.startswith('/') or 'found:' in line_lower:
                    found_count += 1
                    if found_count % 5 == 0:  # Update every 5 findings
                        progress = min(0.1 + (found_count / 50) * 0.8, 0.9)
                        progress_bar.progress(progress)
                        status_text.text(f"Found {found_count} items...")
                
                # Show progress indicators
                if 'progress:' in line_lower or '%' in output_line:
                    status_text.text(f"Scanning... {output_line.strip()[:60]}...")
                
                # Show specific findings in real-time
                if output_line.startswith('/') and '(Status:' in output_line:
                    path = output_line.split(' ')[0]
                    status_text.text(f"Found: {path}")
                
                # Update monitoring dashboard every 3 seconds during scan
                current_time = time.time()
                if current_time - last_monitor_update > 3.0:
                    try:
                        current_metrics = monitor.get_latest_metrics()
                        if current_metrics:
                            status_text.text(f"Scanning... | CPU: {current_metrics.cpu_percent:.1f}% | Memory: {current_metrics.memory_percent:.1f}% | Found: {found_count}")
                        last_monitor_update = current_time
                    except:
                        pass
        
        # Get any remaining output
        remaining_output, error_output = process.communicate()
        output += remaining_output
        
        progress_bar.progress(1.0)
        status_text.text("Gobuster scan completed!")
        
        return output, error_output, process.returncode
        
    except Exception as e:
        return "", str(e), 1

def create_gobuster_html_report(scan_results, scan_command):
    """Create an HTML report of the Gobuster scan results"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gobuster Directory/File Brute-Force Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #2E86AB; color: white; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; padding: 15px; border-radius: 5px; }}
            .found {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; }}
            .info {{ background-color: #e3f2fd; border-left: 4px solid #2196f3; }}
            .summary {{ background-color: #f1f8e9; border-left: 4px solid #4caf50; }}
            .warning {{ background-color: #fff3e0; border-left: 4px solid #ff9800; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .command {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; }}
            .status-200 {{ color: #2e7d32; font-weight: bold; }}
            .status-300 {{ color: #f57c00; font-weight: bold; }}
            .status-400 {{ color: #d32f2f; font-weight: bold; }}
            .status-500 {{ color: #7b1fa2; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 Gobuster {scan_results.get('mode', 'Directory/File').upper()} Scan Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section summary">
            <h2>📊 Scan Summary</h2>
            <p><strong>Target:</strong> {scan_results.get('target', 'N/A')}</p>
            <p><strong>Scan Mode:</strong> {scan_results.get('mode', 'N/A').upper()}</p>
            <p><strong>Wordlist Size:</strong> {scan_results.get('wordlist_size', 0):,} entries</p>
            <p><strong>Items Found:</strong> {len(scan_results.get('found_items', []))}</p>
            <p><strong>Requests/sec:</strong> {scan_results.get('scan_stats', {}).get('requests_per_second', 'N/A')}</p>
            <p><strong>Total Time:</strong> {scan_results.get('scan_stats', {}).get('total_time', 'N/A')} seconds</p>
        </div>
        
        <div class="section">
            <h2>⚙️ Command Used</h2>
            <div class="command">{scan_command}</div>
        </div>
    """
    
    # Add status code breakdown
    if scan_results.get('status_codes'):
        html_content += """
        <div class="section info">
            <h2>📈 Status Code Breakdown</h2>
            <table>
                <tr><th>Status Code</th><th>Count</th><th>Description</th></tr>
        """
        
        status_descriptions = {
            200: "OK - Resource found",
            301: "Moved Permanently",
            302: "Found (Temporary Redirect)",
            403: "Forbidden - Access denied",
            404: "Not Found",
            500: "Internal Server Error"
        }
        
        for status_code, count in sorted(scan_results['status_codes'].items()):
            status_class = f"status-{str(status_code)[0]}00"
            description = status_descriptions.get(status_code, "Unknown")
            html_content += f"""
                <tr>
                    <td class="{status_class}">{status_code}</td>
                    <td>{count}</td>
                    <td>{description}</td>
                </tr>
            """
        
        html_content += "</table></div>"
    
    # Add found items section
    if scan_results.get('found_items'):
        html_content += """
        <div class="section found">
            <h2>🎯 Discovered Items</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Path/Name</th>
                    <th>Status</th>
                    <th>Size</th>
                    <th>Full URL</th>
                </tr>
        """
        
        for item in scan_results['found_items']:
            status_class = f"status-{str(item.get('status_code', 0))[0]}00" if item.get('status_code') else ""
            size_display = f"{item.get('size', 0):,} bytes" if item.get('size') else "N/A"
            
            # Handle DNS results with IP addresses
            if item.get('type') == 'Subdomain' and item.get('ip_addresses'):
                path_display = f"{item.get('path', 'N/A')}<br><small>IPs: {', '.join(item.get('ip_addresses', []))}</small>"
            else:
                path_display = f"<code>{item.get('path', 'N/A')}</code>"
            
            html_content += f"""
                <tr>
                    <td>{item.get('type', 'N/A')}</td>
                    <td>{path_display}</td>
                    <td class="{status_class}">{item.get('status_code', 'N/A')}</td>
                    <td>{size_display}</td>
                    <td><a href="{item.get('full_url', '#')}" target="_blank">{item.get('full_url', 'N/A')}</a></td>
                </tr>
            """
        
        html_content += "</table></div>"
    else:
        html_content += """
        <div class="section info">
            <h2>🔍 No Items Found</h2>
            <p>No directories, files, or resources were discovered with the provided wordlist and configuration.</p>
            <p><strong>Suggestions:</strong></p>
            <ul>
                <li>Try a different wordlist with more common directory/file names</li>
                <li>Adjust the file extensions being tested</li>
                <li>Check if the target URL is accessible</li>
                <li>Verify the target is a web server</li>
            </ul>
        </div>
        """
    
    # Add raw output section
    html_content += f"""
        <div class="section">
            <h2>📄 Raw Gobuster Output</h2>
            <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto;">{scan_results.get('raw_output', '')}</pre>
        </div>
        
        <div class="section">
            <p><em>Report generated by XKRed27 Security Suite - Gobuster Scanner</em></p>
        </div>
    </body>
    </html>
    """
    
    return html_content

def show_gobuster_interface():
    """Main Gobuster directory/file brute-forcer interface"""
    st.header("🔍 Gobuster Directory/File Brute-Forcer")
    
    st.info("💡 **Gobuster** is a directory/file & DNS busting tool written in Go. It's designed to be fast and efficient for discovering hidden directories, files, and subdomains on web servers.")
    
    # System Performance Monitoring
    st.markdown("### 📊 System Performance Monitor")
    monitor = get_global_monitor()
    monitoring_container = st.container()
    create_monitoring_dashboard(monitor, monitoring_container)
    
    # Configuration section
    st.subheader("⚙️ Directory/File Brute-Force Configuration")
    
    # Create columns for better organization
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Target specification
        st.markdown("### 🎯 Target Specification")
        
        # Check for discovered hosts
        discovered_hosts = get_discovered_hosts_for_dropdown()
        
        if discovered_hosts:
            st.markdown("#### 📡 Select from Network Discovery")
            selected_host = st.selectbox(
                "Choose a discovered host:",
                options=[""] + discovered_hosts,
                help="Hosts discovered by the Network Discovery scanner. Selection will auto-populate the target field below.",
                key="gobuster_host_selectbox"
            )
            
            # Auto-populate target field when selection changes
            if selected_host:
                selected_ip = extract_ip_from_selection(selected_host)
                st.session_state.gobuster_target_from_discovery = selected_ip
                st.success(f"✅ Auto-populated target: {selected_ip}")
            
            st.markdown("#### ✍️ Target Configuration")
        else:
            st.markdown("#### ✍️ Target Configuration")
        
        # Target input modes
        target_mode = st.radio(
            "Target Input Mode:",
            ["URL", "IP Address", "IP:Port"],
            help="Choose how to specify the target",
            key="gobuster_target_mode"
        )
        
        # Initialize target input with discovered host if selected
        initial_target = ""
        if 'gobuster_target_from_discovery' in st.session_state:
            initial_target = st.session_state.gobuster_target_from_discovery
        
        # Initialize target input value in session state if not exists
        if "gobuster_target_input" not in st.session_state:
            st.session_state.gobuster_target_input = initial_target
        elif initial_target:  # Update if we have a new target from discovery
            st.session_state.gobuster_target_input = initial_target
        
        if target_mode == "URL":
            target_input = st.text_input(
                "Target URL",
                value=st.session_state.gobuster_target_input if st.session_state.gobuster_target_input.startswith('http') else "",
                placeholder="https://example.com or http://192.168.1.100",
                help="Enter the full URL including protocol (http:// or https://)",
                key="gobuster_url_input"
            )
        elif target_mode == "IP Address":
            target_input = st.text_input(
                "Target IP Address",
                value=st.session_state.gobuster_target_input if not st.session_state.gobuster_target_input.startswith('http') else "",
                placeholder="192.168.1.100",
                help="Enter IP address (will use HTTP on port 80 by default)",
                key="gobuster_ip_input"
            )
        else:  # IP:Port
            target_input = st.text_input(
                "Target IP:Port",
                value=st.session_state.gobuster_target_input if ':' in st.session_state.gobuster_target_input else "",
                placeholder="192.168.1.100:8080",
                help="Enter IP address and port separated by colon",
                key="gobuster_ip_port_input"
            )
        
        # Clear the discovery target after use
        if 'gobuster_target_from_discovery' in st.session_state:
            del st.session_state.gobuster_target_from_discovery
    
    with col2:
        # Scan mode selection
        st.markdown("### 🔧 Scan Mode")
        
        scan_mode = st.selectbox(
            "Gobuster Mode",
            [
                "dir - Directory/File brute-forcing",
                "dns - DNS subdomain brute-forcing", 
                "vhost - Virtual host brute-forcing",
                "fuzz - Fuzzing mode for parameter discovery",
                "s3 - AWS S3 bucket enumeration"
            ],
            help="Select the type of brute-forcing to perform"
        )
        
        # Extract mode code
        mode_code = scan_mode.split(' - ')[0]
        
        # Protocol selection (for dir and vhost modes)
        if mode_code in ['dir', 'vhost']:
            use_https = st.checkbox("Use HTTPS", help="Use HTTPS instead of HTTP")
        
        # Additional options based on mode
        if mode_code == 'dir':
            st.markdown("**Directory Options**")
            include_status_codes = st.multiselect(
                "Include Status Codes",
                ["200", "204", "301", "302", "307", "401", "403"],
                default=["200", "204", "301", "302", "307", "401", "403"],
                help="Status codes to include in results"
            )
            
            # Additional directory-specific options
            col_dir1, col_dir2 = st.columns(2)
            
            with col_dir1:
                add_slash = st.checkbox("Add Slash", value=False, help="Append / to each request")
                discover_backup = st.checkbox("Discover Backup Files", value=False, help="Search for backup files when files are found")
                expanded_mode = st.checkbox("Expanded Mode", value=False, help="Print full URLs in results")
                hide_length = st.checkbox("Hide Length", value=False, help="Hide the length of the body in output")
                wildcard = st.checkbox("Force Wildcard", value=False, help="Force continued operation when wildcard found")
            
            with col_dir2:
                custom_method = st.text_input("HTTP Method", value="GET", help="Custom HTTP method (default: GET)")
                custom_useragent = st.text_input("Custom User-Agent", placeholder="Mozilla/5.0...", help="Custom User-Agent string")
                proxy = st.text_input("Proxy", placeholder="http://proxy:8080", help="Proxy to use for requests")
                cookies = st.text_input("Cookies", placeholder="session=abc123", help="Cookies to use for requests")
            
            # HTTP Headers
            st.markdown("**HTTP Headers**")
            header1 = st.text_input("Header 1", placeholder="Authorization: Bearer token", help="Custom HTTP header (format: Name: Value)")
            header2 = st.text_input("Header 2", placeholder="X-API-Key: key123", help="Additional HTTP header")
            header3 = st.text_input("Header 3", placeholder="Accept: application/json", help="Additional HTTP header")
            
            # Basic Authentication
            st.markdown("**Basic Authentication**")
            basic_auth = st.checkbox("Use Basic Auth", value=False, help="Enable HTTP Basic Authentication")
            if basic_auth:
                col_auth1, col_auth2 = st.columns(2)
                with col_auth1:
                    auth_username = st.text_input("Username", placeholder="admin", help="Basic Auth username")
                with col_auth2:
                    auth_password = st.text_input("Password", placeholder="password", help="Basic Auth password")
        elif mode_code == 'dns':
            st.markdown("**DNS Subdomain Options**")
            
            col_dns1, col_dns2 = st.columns(2)
            
            with col_dns1:
                custom_resolver = st.text_input("Custom DNS Resolver", placeholder="8.8.8.8", help="Use custom DNS server (e.g., 8.8.8.8 or 8.8.8.8:53)")
                show_cname = st.checkbox("Show CNAME Records", value=False, help="Show CNAME records (cannot be used with Show IPs)")
                show_ips = st.checkbox("Show IP Addresses", value=False, help="Show IP addresses (cannot be used with Show CNAME)")
                wildcard_dns = st.checkbox("Force Wildcard", value=False, help="Force continued operation when wildcard found")
            
            with col_dns2:
                dns_timeout = st.slider("DNS Timeout (seconds)", min_value=1, max_value=30, value=1, help="DNS resolver timeout")
                no_fqdn = st.checkbox("No FQDN", value=False, help="Don't add trailing dot to domain")
                dns_protocol = st.selectbox("DNS Protocol", ["udp", "tcp"], help="Protocol for custom resolver")
                st.info("💡 **Note:** CNAME and IP display are mutually exclusive - choose one or neither")
        elif mode_code == 'vhost':
            st.markdown("**VHOST Enumeration Options**")
            
            col_vhost1, col_vhost2 = st.columns(2)
            
            with col_vhost1:
                vhost_cookies = st.text_input("Cookies", placeholder="session=abc123", help="Cookies to use for requests")
                vhost_follow_redirects = st.checkbox("Follow Redirects", value=False, help="Follow HTTP redirects")
                vhost_custom_method = st.text_input("HTTP Method", value="GET", help="Custom HTTP method (default: GET)")
                vhost_no_tls_validation = st.checkbox("Skip TLS Validation", value=False, help="Skip TLS certificate verification")
                vhost_random_agent = st.checkbox("Random User-Agent", value=False, help="Use random User-Agent strings")
            
            with col_vhost2:
                vhost_timeout = st.slider("HTTP Timeout (seconds)", min_value=1, max_value=60, value=10, help="HTTP request timeout")
                vhost_custom_useragent = st.text_input("Custom User-Agent", placeholder="Mozilla/5.0...", help="Custom User-Agent string")
                vhost_proxy = st.text_input("Proxy", placeholder="http://proxy:8080", help="Proxy to use for requests")
                vhost_basic_auth = st.checkbox("Use Basic Auth", value=False, help="Enable HTTP Basic Authentication")
            
            # VHOST HTTP Headers
            st.markdown("**VHOST HTTP Headers**")
            vhost_header1 = st.text_input("VHOST Header 1", placeholder="Host: example.com", help="Custom HTTP header (format: Name: Value)")
            vhost_header2 = st.text_input("VHOST Header 2", placeholder="X-Forwarded-For: 127.0.0.1", help="Additional HTTP header")
            vhost_header3 = st.text_input("VHOST Header 3", placeholder="Accept: application/json", help="Additional HTTP header")
            
            # VHOST Basic Authentication
            if vhost_basic_auth:
                col_vhost_auth1, col_vhost_auth2 = st.columns(2)
                with col_vhost_auth1:
                    vhost_auth_username = st.text_input("VHOST Username", placeholder="admin", help="Basic Auth username")
                with col_vhost_auth2:
                    vhost_auth_password = st.text_input("VHOST Password", placeholder="password", help="Basic Auth password")
        elif mode_code == 'fuzz':
            st.markdown("**Fuzzing Options**")
            fuzz_parameter = st.text_input(
                "Parameter to Fuzz",
                value="FUZZ",
                help="Parameter name to fuzz (e.g., FUZZ, id, page)"
            )
            fuzz_method = st.selectbox(
                "HTTP Method",
                ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                help="HTTP method to use for fuzzing"
            )
        elif mode_code == 's3':
            st.markdown("**S3 Bucket Options**")
            st.info("S3 mode will enumerate AWS S3 buckets")
            s3_region = st.selectbox(
                "AWS Region",
                ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "auto"],
                help="AWS region for bucket enumeration"
            )
    
    # Wordlist configuration
    st.markdown("### 📚 Wordlist Configuration")
    
    wordlist_mode = st.radio(
        "Wordlist Source:",
        ["Built-in Wordlists", "Upload Custom Wordlist", "Manual Entry"],
        help="Choose how to provide the wordlist for brute-forcing",
        key="gobuster_wordlist_mode"
    )
    
    wordlist_path = ""
    wordlist_content = ""
    
    if wordlist_mode == "Built-in Wordlists":
        col_wl1, col_wl2 = st.columns(2)
        
        with col_wl1:
            if mode_code == 'dir':
                builtin_wordlist = st.selectbox(
                    "Directory Wordlist",
                    [
                        "common.txt - Common directories/files",
                        "medium.txt - Medium directory list", 
                        "big.txt - Large directory list",
                        "raft-medium-directories.txt - Raft medium dirs",
                        "raft-large-directories.txt - Raft large dirs"
                    ],
                    help="Select a built-in directory wordlist"
                )
            elif mode_code == 'dns':
                builtin_wordlist = st.selectbox(
                    "Subdomain Wordlist",
                    [
                        "subdomains-top1million-5000.txt - Top 5k subdomains",
                        "subdomains-top1million-20000.txt - Top 20k subdomains",
                        "dns-Jhaddix.txt - Jhaddix DNS list",
                        "fierce-hostlist.txt - Fierce hostlist"
                    ],
                    help="Select a built-in subdomain wordlist"
                )
            elif mode_code == 'vhost':
                builtin_wordlist = st.selectbox(
                    "Virtual Host Wordlist",
                    [
                        "virtual-host-scanning.txt - Common vhosts",
                        "subdomains-top1million-5000.txt - Top subdomains as vhosts"
                    ],
                    help="Select a built-in virtual host wordlist"
                )
            elif mode_code == 'fuzz':
                builtin_wordlist = st.selectbox(
                    "Fuzzing Wordlist",
                    [
                        "common.txt - Common parameter values",
                        "medium.txt - Medium parameter list",
                        "big.txt - Large parameter list",
                        "raft-medium-words.txt - Raft medium words",
                        "numbers.txt - Sequential numbers (1-10000)"
                    ],
                    help="Select a built-in fuzzing wordlist"
                )
            else:  # s3
                builtin_wordlist = st.selectbox(
                    "S3 Bucket Wordlist",
                    [
                        "s3-buckets.txt - Common S3 bucket names",
                        "subdomains-top1million-5000.txt - Subdomains as bucket names",
                        "company-names.txt - Company name variations",
                        "generic-buckets.txt - Generic bucket patterns"
                    ],
                    help="Select a built-in S3 bucket wordlist"
                )
        
        with col_wl2:
            st.info("💡 Built-in wordlists are commonly used lists for web discovery")
            
            # Show estimated wordlist size
            wordlist_sizes = {
                "common.txt": "~4,600 entries",
                "medium.txt": "~20,000 entries", 
                "big.txt": "~81,000 entries",
                "subdomains-top1million-5000.txt": "~5,000 entries",
                "subdomains-top1million-20000.txt": "~20,000 entries"
            }
            
            selected_list = builtin_wordlist.split(' - ')[0]
            estimated_size = wordlist_sizes.get(selected_list, "Size varies")
            st.metric("Estimated Size", estimated_size)
    
    elif wordlist_mode == "Upload Custom Wordlist":
        uploaded_wordlist = st.file_uploader(
            "Upload Wordlist File",
            type=["txt", "lst", "dic"],
            help="Upload a custom wordlist file (one entry per line)",
            key="gobuster_wordlist_uploader"
        )
        
        if uploaded_wordlist:
            st.session_state['gobuster_wordlist_file'] = uploaded_wordlist
            st.success(f"📁 Uploaded: {uploaded_wordlist.name}")
            
            # Show file stats
            file_content = uploaded_wordlist.getvalue().decode('utf-8')
            line_count = len(file_content.strip().split('\n'))
            st.metric("Wordlist Size", f"{line_count:,} entries")
            
        elif 'gobuster_wordlist_file' in st.session_state:
            uploaded_wordlist = st.session_state['gobuster_wordlist_file']
            st.info(f"📁 Using uploaded: {uploaded_wordlist.name}")
    
    elif wordlist_mode == "Manual Entry":
        wordlist_content = st.text_area(
            "Enter Wordlist",
            placeholder="admin\nconfig\ntest\nbackup\napi\nwp-admin",
            help="Enter words/paths to test (one per line)",
            height=150
        )
        
        if wordlist_content:
            line_count = len(wordlist_content.strip().split('\n'))
            st.metric("Wordlist Size", f"{line_count} entries")
    
    # File extensions (for directory mode)
    if mode_code == 'dir':
        st.markdown("### 📄 File Extensions")
        
        use_extensions = st.checkbox("Test File Extensions", help="Test common file extensions")
        
        if use_extensions:
            col_ext1, col_ext2 = st.columns(2)
            
            with col_ext1:
                common_extensions = st.multiselect(
                    "Common Extensions",
                    ["php", "html", "htm", "asp", "aspx", "jsp", "js", "txt", "xml", "json"],
                    default=["php", "html", "txt"],
                    help="Select common file extensions to test"
                )
            
            with col_ext2:
                custom_extensions = st.text_input(
                    "Custom Extensions",
                    placeholder="pdf,doc,zip",
                    help="Enter additional extensions (comma-separated, no dots)"
                )
                
                if custom_extensions:
                    custom_ext_list = [ext.strip().replace('.', '') for ext in custom_extensions.split(',')]
                    st.write(f"Custom extensions: {', '.join(custom_ext_list)}")
    
    # Get optimal thread recommendations
    thread_recommendations = get_optimal_thread_count()
    
    # Advanced options
    st.markdown("### ⚙️ Advanced Options")
    
    # Performance recommendations
    with st.expander("💡 Performance Recommendations", expanded=False):
        st.write("**Recommended Thread Counts Based on Your System:**")
        col_rec1, col_rec2, col_rec3, col_rec4 = st.columns(4)
        
        with col_rec1:
            st.metric("🐌 Conservative", min(thread_recommendations["conservative"], 10), "Safe for web servers")
        with col_rec2:
            st.metric("⚖️ Moderate", min(thread_recommendations["moderate"], 25), "Good balance")
        with col_rec3:
            st.metric("🚀 Aggressive", min(thread_recommendations["aggressive"], 50), "High performance")
        with col_rec4:
            st.metric("🔥 Maximum", min(thread_recommendations["maximum"], 100), "Use with caution")
        
        st.warning("⚠️ **Web Server Consideration**: High thread counts may overwhelm web servers or trigger rate limiting. Start conservative for production targets.")
    
    # Create columns for advanced options
    col_adv1, col_adv2, col_adv3, col_adv4 = st.columns(4)
    
    with col_adv1:
        threads = st.slider(
            "Threads", 
            min_value=1, 
            max_value=100, 
            value=min(thread_recommendations["moderate"], 25), 
            help="Number of concurrent threads. Be careful with high values on production servers."
        )
        timeout = st.slider("Timeout (seconds)", min_value=1, max_value=60, value=10, help="HTTP request timeout")
    
    with col_adv2:
        delay = st.slider("Delay (ms)", min_value=0, max_value=5000, value=0, help="Delay between requests in milliseconds")
        follow_redirects = st.checkbox("Follow Redirects", value=False, help="Follow HTTP redirects")
    
    with col_adv3:
        verbose = st.checkbox("Verbose Output", value=True, help="Show verbose output")
        quiet = st.checkbox("Quiet Mode", value=False, help="Reduce output verbosity")
        no_error = st.checkbox("Hide Errors", value=False, help="Don't display error messages")
        
        if mode_code == 'dir':
            no_status = st.checkbox("Hide Status", value=False, help="Don't display status codes")
    
    with col_adv4:
        no_progress = st.checkbox("Hide Progress", value=False, help="Don't display progress bar")
        output_file = st.text_input("Output File", placeholder="results.txt", help="Save results to file (optional)")
        pattern_file = st.text_input("Pattern File", placeholder="patterns.txt", help="File containing replacement patterns")
        random_agent = st.checkbox("Random User-Agent", value=False, help="Use random User-Agent strings")
        no_tls_validation = st.checkbox("Skip TLS Validation", value=False, help="Skip TLS certificate verification")
    
    # Scan Configuration Display
    st.markdown("### 🎯 Scan Configuration")
    
    if target_input and target_input.strip():
        # Validate target based on mode
        valid_target = False
        final_target = target_input.strip()
        
        if target_mode == "URL":
            valid_target = validate_url(final_target)
            if not valid_target:
                st.error("❌ Invalid URL format. Please use http://example.com or https://example.com")
        elif target_mode == "IP Address":
            valid_target = validate_ip(final_target)
            if valid_target:
                protocol = "https" if (mode_code in ['dir', 'vhost'] and use_https) else "http"
                final_target = f"{protocol}://{final_target}"
            else:
                st.error("❌ Invalid IP address format")
        else:  # IP:Port
            if ':' in final_target:
                ip, port_str = final_target.split(':', 1)
                try:
                    port_num = int(port_str)
                    valid_target = validate_ip(ip) and 1 <= port_num <= 65535
                    if valid_target:
                        protocol = "https" if (mode_code in ['dir', 'vhost'] and use_https) else "http"
                        final_target = f"{protocol}://{ip}:{port_num}"
                    else:
                        st.error("❌ Invalid IP address or port")
                except ValueError:
                    st.error("❌ Invalid port number")
            else:
                st.error("❌ Please use IP:Port format (e.g., 192.168.1.100:8080)")
        
        if valid_target:
            st.write(f"**Target:** {final_target}")
            st.write(f"**Mode:** {mode_code.upper()} ({scan_mode.split(' - ')[1]})")
            st.write(f"**Wordlist:** {wordlist_mode}")
            st.write(f"**Threads:** {threads}, **Timeout:** {timeout}s")
            
            # Show additional options
            additional_opts = []
            if delay > 0:
                additional_opts.append(f"Delay: {delay}ms")
            if follow_redirects:
                additional_opts.append("Follow Redirects: Yes")
            if no_error:
                additional_opts.append("Hide Errors: Yes")
            if no_progress:
                additional_opts.append("Hide Progress: Yes")
            if output_file and output_file.strip():
                additional_opts.append(f"Output File: {output_file.strip()}")
            if pattern_file and pattern_file.strip():
                additional_opts.append(f"Pattern File: {pattern_file.strip()}")
            if random_agent:
                additional_opts.append("Random User-Agent: Yes")
            if no_tls_validation:
                additional_opts.append("Skip TLS Validation: Yes")
            
            if additional_opts:
                st.write(f"**Additional Options:** {', '.join(additional_opts)}")
            
            # Show output file location if specified
            if output_file and output_file.strip():
                output_path = output_file.strip()
                if not os.path.isabs(output_path):
                    output_path = os.path.join(os.getcwd(), output_path)
                st.info(f"📁 **Output File:** Results will be saved to `{output_path}`")
            
            # Show directory-specific options
            if mode_code == 'dir':
                dir_opts = []
                if add_slash:
                    dir_opts.append("Add Slash: Yes")
                if discover_backup:
                    dir_opts.append("Discover Backup: Yes")
                if expanded_mode:
                    dir_opts.append("Expanded Mode: Yes")
                if hide_length:
                    dir_opts.append("Hide Length: Yes")
                if wildcard:
                    dir_opts.append("Force Wildcard: Yes")
                if custom_method and custom_method.strip() != "GET":
                    dir_opts.append(f"HTTP Method: {custom_method.strip()}")
                if custom_useragent and custom_useragent.strip():
                    dir_opts.append("Custom User-Agent: Yes")
                if proxy and proxy.strip():
                    dir_opts.append("Proxy: Yes")
                if cookies and cookies.strip():
                    dir_opts.append("Cookies: Yes")
                if basic_auth:
                    dir_opts.append("Basic Auth: Yes")
                if header1 and header1.strip() or header2 and header2.strip() or header3 and header3.strip():
                    dir_opts.append("Custom Headers: Yes")
                
                if dir_opts:
                    st.write(f"**Directory Options:** {', '.join(dir_opts)}")
            
            # Show DNS-specific options
            elif mode_code == 'dns':
                dns_opts = []
                if custom_resolver and custom_resolver.strip():
                    dns_opts.append(f"Custom Resolver: {custom_resolver.strip()}")
                if show_cname:
                    dns_opts.append("Show CNAME: Yes")
                if show_ips:
                    dns_opts.append("Show IPs: Yes")
                if wildcard_dns:
                    dns_opts.append("Force Wildcard: Yes")
                if dns_timeout and dns_timeout != 1:
                    dns_opts.append(f"DNS Timeout: {dns_timeout}s")
                if no_fqdn:
                    dns_opts.append("No FQDN: Yes")
                if dns_protocol and dns_protocol != "udp":
                    dns_opts.append(f"DNS Protocol: {dns_protocol.upper()}")
                
                if dns_opts:
                    st.write(f"**DNS Options:** {', '.join(dns_opts)}")
            
            # Show VHOST-specific options
            elif mode_code == 'vhost':
                vhost_opts = []
                if vhost_cookies and vhost_cookies.strip():
                    vhost_opts.append("Cookies: Yes")
                if vhost_follow_redirects:
                    vhost_opts.append("Follow Redirects: Yes")
                if vhost_custom_method and vhost_custom_method.strip() != "GET":
                    vhost_opts.append(f"HTTP Method: {vhost_custom_method.strip()}")
                if vhost_no_tls_validation:
                    vhost_opts.append("Skip TLS Validation: Yes")
                if vhost_random_agent:
                    vhost_opts.append("Random User-Agent: Yes")
                if vhost_timeout and vhost_timeout != 10:
                    vhost_opts.append(f"HTTP Timeout: {vhost_timeout}s")
                if vhost_custom_useragent and vhost_custom_useragent.strip():
                    vhost_opts.append("Custom User-Agent: Yes")
                if vhost_proxy and vhost_proxy.strip():
                    vhost_opts.append("Proxy: Yes")
                if vhost_basic_auth:
                    vhost_opts.append("Basic Auth: Yes")
                if vhost_header1 and vhost_header1.strip() or vhost_header2 and vhost_header2.strip() or vhost_header3 and vhost_header3.strip():
                    vhost_opts.append("Custom Headers: Yes")
                
                if vhost_opts:
                    st.write(f"**VHOST Options:** {', '.join(vhost_opts)}")
            
            if mode_code == 'dir' and use_extensions:
                all_extensions = common_extensions[:]
                if custom_extensions:
                    all_extensions.extend([ext.strip().replace('.', '') for ext in custom_extensions.split(',')])
                st.write(f"**Extensions:** {', '.join(all_extensions)}")
    else:
        st.info("📝 Please enter a target above to see scan configuration.")
    
    # Start scan button
    if st.button("🚀 Start Gobuster Scan", type="primary", use_container_width=True, key="gobuster_start_scan_btn"):
        if not target_input or not target_input.strip():
            st.error("❌ Please enter a target URL, IP address, or IP:Port")
        else:
            # Validate wordlist
            wordlist_valid = False
            wordlist_error = ""
            
            if wordlist_mode == "Built-in Wordlists":
                wordlist_valid = True  # We'll use a placeholder path for built-in lists
            elif wordlist_mode == "Upload Custom Wordlist":
                if 'gobuster_wordlist_file' in st.session_state:
                    wordlist_valid = True
                else:
                    wordlist_error = "Please upload a wordlist file."
            elif wordlist_mode == "Manual Entry":
                if wordlist_content and wordlist_content.strip():
                    wordlist_valid = True
                else:
                    wordlist_error = "Please enter wordlist content."
            
            if not wordlist_valid:
                st.error(f"❌ Wordlist configuration error: {wordlist_error}")
            elif mode_code == 'dns' and show_cname and show_ips:
                st.error("❌ DNS Configuration Error: Cannot use both 'Show CNAME Records' and 'Show IP Addresses' - they are mutually exclusive")
            else:
                # Validate target
                valid_target = False
                final_target = target_input.strip()
                
                if target_mode == "URL":
                    valid_target = validate_url(final_target)
                elif target_mode == "IP Address":
                    valid_target = validate_ip(final_target)
                    if valid_target:
                        protocol = "https" if (mode_code in ['dir', 'vhost'] and use_https) else "http"
                        final_target = f"{protocol}://{final_target}"
                else:  # IP:Port
                    if ':' in final_target:
                        ip, port_str = final_target.split(':', 1)
                        try:
                            port_num = int(port_str)
                            valid_target = validate_ip(ip) and 1 <= port_num <= 65535
                            if valid_target:
                                protocol = "https" if (mode_code in ['dir', 'vhost'] and use_https) else "http"
                                final_target = f"{protocol}://{ip}:{port_num}"
                        except ValueError:
                            valid_target = False
                
                if not valid_target:
                    st.error("❌ Invalid target format. Please check your input.")
                else:
                    # Build Gobuster command
                    cmd = ["gobuster", mode_code]
                    
                    # Add target URL
                    if mode_code == 'dns':
                        # DNS mode uses --domain for domain
                        domain = final_target.replace('http://', '').replace('https://', '').split('/')[0]
                        cmd.extend(["--domain", domain])
                    elif mode_code == 's3':
                        # S3 mode uses --domain for domain (bucket names)
                        domain = final_target.replace('http://', '').replace('https://', '').split('/')[0]
                        cmd.extend(["--domain", domain])
                    else:
                        # dir, vhost, and fuzz modes use -u for URL
                        cmd.extend(["-u", final_target])
                    
                    # Add wordlist
                    if wordlist_mode == "Built-in Wordlists":
                        # For demo purposes, we'll create a small sample wordlist
                        # In a real implementation, you'd have actual wordlist files
                        sample_words = {
                            'dir': ['admin', 'config', 'test', 'backup', 'api', 'login', 'dashboard', 'panel', 'wp-admin', 'phpmyadmin'],
                            'dns': ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'app', 'blog'],
                            'vhost': ['admin', 'test', 'dev', 'staging', 'api', 'mail', 'ftp', 'blog', 'shop', 'portal'],
                            'fuzz': ['admin', 'user', 'id', 'page', 'file', 'search', 'query', 'param', 'test', 'debug'],
                            's3': ['test', 'dev', 'staging', 'prod', 'backup', 'assets', 'uploads', 'media', 'files', 'data']
                        }
                        
                        # Create temporary wordlist file
                        with open("/tmp/gobuster_wordlist.txt", "w") as f:
                            f.write('\n'.join(sample_words.get(mode_code, sample_words['dir'])))
                        cmd.extend(["-w", "/tmp/gobuster_wordlist.txt"])
                        
                        st.info("💡 Using built-in sample wordlist for demo. In production, use comprehensive wordlists.")
                        
                    elif wordlist_mode == "Upload Custom Wordlist":
                        # Save uploaded wordlist
                        wordlist_file = st.session_state['gobuster_wordlist_file']
                        with open("/tmp/gobuster_wordlist_uploaded.txt", "wb") as f:
                            f.write(wordlist_file.getbuffer())
                        cmd.extend(["-w", "/tmp/gobuster_wordlist_uploaded.txt"])
                        
                    elif wordlist_mode == "Manual Entry":
                        # Create temporary wordlist from manual entry
                        with open("/tmp/gobuster_wordlist_manual.txt", "w") as f:
                            f.write(wordlist_content)
                        cmd.extend(["-w", "/tmp/gobuster_wordlist_manual.txt"])
                    
                    # Add threads
                    cmd.extend(["-t", str(threads)])
                    
                    # Add timeout
                    cmd.extend(["--timeout", f"{timeout}s"])
                    
                    # Add delay if specified
                    if delay > 0:
                        cmd.extend(["--delay", f"{delay}ms"])
                    
                    # Add mode-specific options
                    if mode_code == 'dir':
                        # Add status codes - disable default blacklist and set our own
                        if include_status_codes:
                            cmd.extend(["-s", ",".join(include_status_codes)])
                            # Disable default blacklist (404) by setting it to empty
                            cmd.extend(["-b", ""])
                        
                        # Add extensions
                        if use_extensions:
                            all_extensions = common_extensions[:]
                            if custom_extensions:
                                all_extensions.extend([ext.strip().replace('.', '') for ext in custom_extensions.split(',')])
                            if all_extensions:
                                cmd.extend(["-x", ",".join(all_extensions)])
                        
                        # Add redirect following
                        if follow_redirects:
                            cmd.append("-r")
                        
                        # Add status hiding
                        if no_status:
                            cmd.append("-n")
                        
                        # Add directory-specific flags
                        if add_slash:
                            cmd.append("-f")
                        if discover_backup:
                            cmd.append("-d")
                        if expanded_mode:
                            cmd.append("-e")
                        if hide_length:
                            cmd.append("--hide-length")
                        if wildcard:
                            cmd.append("--wildcard")
                        
                        # Add custom HTTP method
                        if custom_method and custom_method.strip() and custom_method.strip() != "GET":
                            cmd.extend(["-m", custom_method.strip()])
                        
                        # Add custom User-Agent
                        if custom_useragent and custom_useragent.strip():
                            cmd.extend(["-a", custom_useragent.strip()])
                        
                        # Add proxy
                        if proxy and proxy.strip():
                            cmd.extend(["--proxy", proxy.strip()])
                        
                        # Add cookies
                        if cookies and cookies.strip():
                            cmd.extend(["-c", cookies.strip()])
                        
                        # Add HTTP headers
                        headers_to_add = []
                        if header1 and header1.strip():
                            headers_to_add.append(header1.strip())
                        if header2 and header2.strip():
                            headers_to_add.append(header2.strip())
                        if header3 and header3.strip():
                            headers_to_add.append(header3.strip())
                        
                        for header in headers_to_add:
                            cmd.extend(["-H", header])
                        
                        # Add Basic Authentication
                        if basic_auth and auth_username and auth_password:
                            cmd.extend(["-U", auth_username.strip()])
                            cmd.extend(["-P", auth_password.strip()])
                    
                    elif mode_code == 'dns':
                        # DNS mode specific options
                        if custom_resolver and custom_resolver.strip():
                            cmd.extend(["--resolver", custom_resolver.strip()])
                        if show_cname:
                            cmd.append("--check-cname")
                        if show_ips:
                            # Note: show-ips flag doesn't exist in new version, but we can handle it in results parsing
                            pass
                        if wildcard_dns:
                            cmd.append("--wildcard")
                        if dns_timeout and dns_timeout != 1:
                            cmd.extend(["--timeout", f"{dns_timeout}s"])
                        if no_fqdn:
                            cmd.append("--no-fqdn")
                        if dns_protocol and dns_protocol != "udp":
                            cmd.extend(["--protocol", dns_protocol])
                    
                    elif mode_code == 'vhost':
                        # VHOST mode specific options
                        if vhost_follow_redirects:
                            cmd.append("-r")
                        
                        # Add VHOST-specific flags
                        if vhost_cookies and vhost_cookies.strip():
                            cmd.extend(["-c", vhost_cookies.strip()])
                        if vhost_custom_method and vhost_custom_method.strip() and vhost_custom_method.strip() != "GET":
                            cmd.extend(["-m", vhost_custom_method.strip()])
                        if vhost_no_tls_validation:
                            cmd.append("-k")
                        if vhost_random_agent:
                            cmd.append("--random-agent")
                        if vhost_timeout and vhost_timeout != 10:
                            cmd.extend(["--timeout", f"{vhost_timeout}s"])
                        if vhost_custom_useragent and vhost_custom_useragent.strip():
                            cmd.extend(["-a", vhost_custom_useragent.strip()])
                        if vhost_proxy and vhost_proxy.strip():
                            cmd.extend(["--proxy", vhost_proxy.strip()])
                        
                        # Add VHOST HTTP headers
                        vhost_headers_to_add = []
                        if vhost_header1 and vhost_header1.strip():
                            vhost_headers_to_add.append(vhost_header1.strip())
                        if vhost_header2 and vhost_header2.strip():
                            vhost_headers_to_add.append(vhost_header2.strip())
                        if vhost_header3 and vhost_header3.strip():
                            vhost_headers_to_add.append(vhost_header3.strip())
                        
                        for header in vhost_headers_to_add:
                            cmd.extend(["-H", header])
                        
                        # Add VHOST Basic Authentication
                        if vhost_basic_auth and vhost_auth_username and vhost_auth_password:
                            cmd.extend(["-U", vhost_auth_username.strip()])
                            cmd.extend(["-P", vhost_auth_password.strip()])
                    
                    elif mode_code == 'fuzz':
                        # Fuzz mode specific options
                        if fuzz_parameter:
                            cmd.extend(["-w", fuzz_parameter])
                        if fuzz_method and fuzz_method != "GET":
                            cmd.extend(["-m", fuzz_method])
                    
                    elif mode_code == 's3':
                        # S3 mode specific options
                        if s3_region and s3_region != "auto":
                            cmd.extend(["--region", s3_region])
                    
                    # Add verbosity and output options
                    if quiet:
                        cmd.append("-q")
                    elif not verbose:
                        cmd.append("--no-progress")
                    
                    # Add error display options
                    if no_error:
                        cmd.append("--no-error")
                    
                    # Add progress display options
                    if no_progress:
                        cmd.append("-z")
                    
                    # Add output file
                    if output_file and output_file.strip():
                        # Ensure output file has full path and is writable
                        output_path = output_file.strip()
                        if not os.path.isabs(output_path):
                            output_path = os.path.join(os.getcwd(), output_path)
                        
                        # Create directory if it doesn't exist
                        output_dir = os.path.dirname(output_path)
                        if output_dir and not os.path.exists(output_dir):
                            os.makedirs(output_dir, exist_ok=True)
                        
                        # Test if we can write to the file
                        try:
                            with open(output_path, 'w') as f:
                                f.write("# Gobuster Scan Results\n")
                            cmd.extend(["-o", output_path])
                            st.success(f"✅ Output will be saved to: {output_path}")
                        except Exception as e:
                            st.warning(f"⚠️ Cannot write to {output_path}: {str(e)}")
                            st.info("💡 Results will still be displayed in the UI")
                    
                    # Add pattern file
                    if pattern_file and pattern_file.strip():
                        cmd.extend(["-p", pattern_file.strip()])
                    
                    # Add User-Agent options
                    if random_agent:
                        cmd.append("--random-agent")
                    
                    # Add TLS options
                    if no_tls_validation:
                        cmd.append("-k")
                    
                    st.write(f"**Command:** `{' '.join(cmd)}`")
                    
                    # Warning about directory brute-forcing
                    st.warning("⚠️ **Warning:** Directory/file brute-forcing can generate significant traffic and may trigger security systems. Use responsibly and only on authorized systems!")
                    
                    # Progress indicators
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    # Run scan
                    with st.spinner("Starting Gobuster directory/file brute-force scan..."):
                        output, error, return_code = run_gobuster_scan(cmd, progress_bar, status_text)
                    
                    # Clean up temporary files
                    try:
                        temp_files = [
                            "/tmp/gobuster_wordlist.txt",
                            "/tmp/gobuster_wordlist_uploaded.txt",
                            "/tmp/gobuster_wordlist_manual.txt"
                        ]
                        for temp_file in temp_files:
                            if os.path.exists(temp_file):
                                os.remove(temp_file)
                    except:
                        pass
                    
                    if return_code == 0 or output:  # Gobuster might return non-zero even on success
                        st.success("✅ Gobuster scan completed!")
                        
                        # Add clear results button
                        col_clear1, col_clear2 = st.columns([1, 4])
                        with col_clear1:
                            if st.button("🔄 Clear & New Scan", help="Clear results and start a new scan", key="gobuster_clear_new_scan_btn"):
                                # Clear session state
                                if 'last_gobuster_results' in st.session_state:
                                    del st.session_state['last_gobuster_results']
                                if 'last_gobuster_command' in st.session_state:
                                    del st.session_state['last_gobuster_command']
                                st.rerun()
                        
                        # Parse and display results
                        scan_results = parse_gobuster_output(output, mode_code)
                        
                        # Store results in session state for download
                        st.session_state['last_gobuster_results'] = scan_results
                        st.session_state['last_gobuster_command'] = ' '.join(cmd)
                        
                        # Display results
                        st.subheader("📊 Scan Results")
                        
                        # Summary metrics
                        col_metric1, col_metric2, col_metric3, col_metric4 = st.columns(4)
                        with col_metric1:
                            st.metric("Items Found", len(scan_results.get('found_items', [])))
                        with col_metric2:
                            st.metric("Wordlist Size", f"{scan_results.get('wordlist_size', 0):,}")
                        with col_metric3:
                            requests_per_sec = scan_results.get('scan_stats', {}).get('requests_per_second', 0)
                            st.metric("Requests/sec", f"{requests_per_sec:.1f}" if requests_per_sec else "N/A")
                        with col_metric4:
                            total_time = scan_results.get('scan_stats', {}).get('total_time', 0)
                            st.metric("Total Time", f"{total_time:.1f}s" if total_time else "N/A")
                        
                        # Found items section
                        if scan_results.get('found_items'):
                            mode_display = {
                                'dir': 'Directories/Files',
                                'dns': 'Subdomains',
                                'vhost': 'Virtual Hosts',
                                'fuzz': 'Fuzzed Parameters',
                                's3': 'S3 Buckets'
                            }.get(scan_results['mode'], scan_results['mode'].upper())
                            
                            st.subheader(f"🎯 Discovered {mode_display}")
                            
                            # Create DataFrame for found items
                            items_data = []
                            for item in scan_results['found_items']:
                                # Handle DNS results with IP addresses
                                if item.get('type') == 'Subdomain' and item.get('ip_addresses'):
                                    path_display = f"{item.get('path', 'N/A')} (IPs: {', '.join(item.get('ip_addresses', []))})"
                                else:
                                    path_display = item.get('path', 'N/A')
                                
                                items_data.append({
                                    'Type': item.get('type', 'N/A'),
                                    'Path/Name': path_display,
                                    'Status Code': item.get('status_code', 'N/A'),
                                    'Size': f"{item.get('size', 0):,} bytes" if item.get('size') else 'N/A',
                                    'Full URL': item.get('full_url', 'N/A')
                                })
                            
                            if items_data:
                                df_items = pd.DataFrame(items_data)
                                st.dataframe(df_items, use_container_width=True)
                                
                                # Show status code breakdown
                                if scan_results.get('status_codes'):
                                    st.subheader("📈 Status Code Breakdown")
                                    status_data = []
                                    for status_code, count in sorted(scan_results['status_codes'].items()):
                                        status_descriptions = {
                                            200: "OK - Resource found",
                                            301: "Moved Permanently", 
                                            302: "Found (Temporary Redirect)",
                                            403: "Forbidden - Access denied",
                                            404: "Not Found",
                                            500: "Internal Server Error"
                                        }
                                        description = status_descriptions.get(status_code, "Unknown")
                                        status_data.append({
                                            'Status Code': status_code,
                                            'Count': count,
                                            'Description': description
                                        })
                                    
                                    df_status = pd.DataFrame(status_data)
                                    st.dataframe(df_status, use_container_width=True)
                        else:
                            st.info("🔍 No items were discovered with the provided wordlist and configuration.")
                            st.markdown("""
                            **Suggestions:**
                            - Try a different or larger wordlist
                            - Adjust the file extensions being tested
                            - Verify the target URL is accessible
                            - Check if the target has a web server running
                            """)
                        
                        # Raw output section
                        with st.expander("📄 Raw Gobuster Output", expanded=False):
                            st.code(output, language="text")
                        
                        # Output file section (if specified)
                        if output_file and output_file.strip():
                            output_path = output_file.strip()
                            if not os.path.isabs(output_path):
                                output_path = os.path.join(os.getcwd(), output_path)
                            
                            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                                with st.expander(f"📁 Output File: {os.path.basename(output_path)}", expanded=False):
                                    try:
                                        with open(output_path, 'r') as f:
                                            file_content = f.read()
                                        st.code(file_content, language="text")
                                        st.success(f"✅ File saved successfully to: `{output_path}`")
                                    except Exception as e:
                                        st.error(f"❌ Error reading output file: {str(e)}")
                            else:
                                st.warning(f"⚠️ Output file is empty or not found at: `{output_path}`")
                        
                        # Download section
                        st.subheader("💾 Download Results")
                        
                        col_download1, col_download2, col_download3, col_download4 = st.columns(4)
                        
                        with col_download1:
                            # HTML Report
                            html_report = create_gobuster_html_report(scan_results, ' '.join(cmd))
                            st.download_button(
                                label="📄 Download HTML Report",
                                data=html_report,
                                file_name=f"gobuster_scan_{datetime.now().strftime('%Y%m%d_%H%m%S')}.html",
                                mime="text/html"
                            )
                        
                        with col_download2:
                            # JSON Results
                            json_results = json.dumps(scan_results, indent=2, default=str)
                            st.download_button(
                                label="📊 Download JSON Results",
                                data=json_results,
                                file_name=f"gobuster_scan_{datetime.now().strftime('%Y%m%d_%H%m%S')}.json",
                                mime="application/json"
                            )
                        
                        with col_download3:
                            # Raw Output
                            st.download_button(
                                label="📝 Download Raw Output",
                                data=output,
                                file_name=f"gobuster_scan_{datetime.now().strftime('%Y%m%d_%H%m%S')}.txt",
                                mime="text/plain"
                            )
                        
                        with col_download4:
                            # Output File Location (if specified)
                            if output_file and output_file.strip():
                                output_path = output_file.strip()
                                if not os.path.isabs(output_path):
                                    output_path = os.path.join(os.getcwd(), output_path)
                                
                                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                                    # Read the file content for download
                                    try:
                                        with open(output_path, 'r') as f:
                                            file_content = f.read()
                                        st.download_button(
                                            label="📁 Download Output File",
                                            data=file_content,
                                            file_name=os.path.basename(output_path),
                                            mime="text/plain"
                                        )
                                        st.info(f"📍 File saved to: `{output_path}`")
                                    except Exception as e:
                                        st.error(f"❌ Error reading output file: {str(e)}")
                                else:
                                    st.warning("⚠️ Output file is empty or not found")
                                    st.info(f"📍 Expected location: `{output_path}`")
                    
                    else:
                        st.error("❌ Gobuster scan failed!")
                        
                        col_error_clear1, col_error_clear2 = st.columns([1, 4])
                        with col_error_clear1:
                            if st.button("🔄 Try New Scan", help="Clear and try a different scan", key="gobuster_try_new_scan_btn"):
                                st.rerun()
                        
                        if error:
                            st.error(f"**Error:** {error}")
                        
                        if output:
                            st.subheader("📄 Partial Output")
                            st.code(output, language="text")

if __name__ == "__main__":
    show_gobuster_interface()
