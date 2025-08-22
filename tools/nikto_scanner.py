#!/usr/bin/env python3
"""
Nikto Web Scanner Module for Nmap UI Suite
Provides comprehensive web vulnerability scanning capabilities
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
from tools.system_monitor import get_global_monitor, create_monitoring_dashboard

def validate_url(url):
    """Validate URL format"""
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return re.match(url_pattern, url) is not None

def validate_ip_port(ip, port=None):
    """Validate IP address and optional port"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, ip):
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            if port:
                return 1 <= port <= 65535
            return True
    return False

def parse_nikto_output(output):
    """Parse Nikto output and structure it for display"""
    lines = output.split('\n')
    results = {
        'target': '',
        'scan_time': '',
        'server_info': '',
        'vulnerabilities': [],
        'informational': [],
        'total_items_checked': 0,
        'scan_duration': '',
        'raw_output': output
    }
    
    current_vulnerability = {}
    
    for line in lines:
        line = line.strip()
        
        # Extract target information
        if '+ Target IP:' in line:
            results['target'] = line.split('Target IP:')[1].strip()
        elif '+ Target Hostname:' in line:
            results['target'] = line.split('Target Hostname:')[1].strip()
        
        # Extract server information
        if '+ Server:' in line:
            results['server_info'] = line.split('Server:')[1].strip()
        
        # Extract scan timing
        if '+ Start Time:' in line:
            results['scan_time'] = line.split('Start Time:')[1].strip()
        elif '+ End Time:' in line:
            end_time = line.split('End Time:')[1].strip()
            if results['scan_time']:
                results['scan_duration'] = f"{results['scan_time']} - {end_time}"
        
        # Parse vulnerabilities and findings
        if line.startswith('+ ') and any(keyword in line.lower() for keyword in ['vulnerable', 'found', 'detected', 'potential', 'warning']):
            vuln = {
                'description': line[2:],  # Remove '+ ' prefix
                'severity': 'Unknown',
                'type': 'Finding'
            }
            
            # Categorize severity based on keywords
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in ['critical', 'high', 'severe', 'dangerous']):
                vuln['severity'] = 'High'
            elif any(keyword in line_lower for keyword in ['medium', 'moderate', 'warning']):
                vuln['severity'] = 'Medium'
            elif any(keyword in line_lower for keyword in ['low', 'info', 'informational']):
                vuln['severity'] = 'Low'
            else:
                vuln['severity'] = 'Info'
            
            # Categorize finding type
            if any(keyword in line_lower for keyword in ['cgi', 'script', 'php', 'asp']):
                vuln['type'] = 'Script/CGI'
            elif any(keyword in line_lower for keyword in ['directory', 'folder', 'path']):
                vuln['type'] = 'Directory'
            elif any(keyword in line_lower for keyword in ['file', 'config', 'backup']):
                vuln['type'] = 'File'
            elif any(keyword in line_lower for keyword in ['server', 'version', 'banner']):
                vuln['type'] = 'Server Info'
            elif any(keyword in line_lower for keyword in ['cookie', 'header', 'http']):
                vuln['type'] = 'HTTP Header'
            
            if vuln['severity'] in ['High', 'Medium']:
                results['vulnerabilities'].append(vuln)
            else:
                results['informational'].append(vuln)
        
        # Count total items checked
        if 'items checked:' in line.lower():
            try:
                count_match = re.search(r'(\d+)\s+items?\s+checked', line.lower())
                if count_match:
                    results['total_items_checked'] = int(count_match.group(1))
            except:
                pass
    
    return results

def run_nikto_scan(command, progress_bar, status_text):
    """Run Nikto scan with progress updates and monitoring"""
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
        items_checked = 0
        last_monitor_update = time.time()
        
        status_text.text("Starting Nikto web vulnerability scan...")
        progress_bar.progress(0.1)
        
        # Read output line by line
        while True:
            output_line = process.stdout.readline()
            if output_line == '' and process.poll() is not None:
                break
            if output_line:
                output += output_line
                line_lower = output_line.lower()
                
                # Update progress based on scan progress indicators
                if 'scanning' in line_lower or 'testing' in line_lower:
                    items_checked += 1
                    if items_checked % 10 == 0:  # Update every 10 items
                        progress = min(0.1 + (items_checked / 1000) * 0.8, 0.9)
                        progress_bar.progress(progress)
                        status_text.text(f"Scanning... {items_checked} items checked")
                
                # Show specific findings in real-time
                if output_line.startswith('+ '):
                    finding = output_line[2:].strip()[:60]
                    status_text.text(f"Found: {finding}...")
                
                # Update monitoring dashboard every 3 seconds during scan
                current_time = time.time()
                if current_time - last_monitor_update > 3.0:
                    try:
                        current_metrics = monitor.get_latest_metrics()
                        if current_metrics:
                            status_text.text(f"Scanning... | CPU: {current_metrics.cpu_percent:.1f}% | Memory: {current_metrics.memory_percent:.1f}%")
                        last_monitor_update = current_time
                    except:
                        pass
        
        # Get any remaining output
        remaining_output, error_output = process.communicate()
        output += remaining_output
        
        progress_bar.progress(1.0)
        status_text.text("Nikto scan completed!")
        
        return output, error_output, process.returncode
        
    except Exception as e:
        return "", str(e), 1

def create_nikto_html_report(scan_results, scan_command):
    """Create an HTML report of the Nikto scan results"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Nikto Web Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #2E86AB; color: white; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; padding: 15px; border-radius: 5px; }}
            .vulnerability {{ background-color: #ffebee; border-left: 4px solid #f44336; }}
            .info {{ background-color: #e3f2fd; border-left: 4px solid #2196f3; }}
            .summary {{ background-color: #f1f8e9; border-left: 4px solid #4caf50; }}
            .high {{ color: #d32f2f; font-weight: bold; }}
            .medium {{ color: #f57c00; font-weight: bold; }}
            .low {{ color: #388e3c; }}
            .info-severity {{ color: #1976d2; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .command {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 Nikto Web Vulnerability Scan Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section summary">
            <h2>📊 Scan Summary</h2>
            <p><strong>Target:</strong> {scan_results.get('target', 'N/A')}</p>
            <p><strong>Server:</strong> {scan_results.get('server_info', 'N/A')}</p>
            <p><strong>Scan Duration:</strong> {scan_results.get('scan_duration', 'N/A')}</p>
            <p><strong>Items Checked:</strong> {scan_results.get('total_items_checked', 0)}</p>
            <p><strong>Vulnerabilities Found:</strong> {len(scan_results.get('vulnerabilities', []))}</p>
            <p><strong>Informational Items:</strong> {len(scan_results.get('informational', []))}</p>
        </div>
        
        <div class="section">
            <h2>⚙️ Command Used</h2>
            <div class="command">{scan_command}</div>
        </div>
    """
    
    # Add vulnerabilities section
    if scan_results.get('vulnerabilities'):
        html_content += """
        <div class="section vulnerability">
            <h2>🚨 Vulnerabilities and Security Issues</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Description</th>
                </tr>
        """
        
        for vuln in scan_results['vulnerabilities']:
            severity_class = vuln['severity'].lower()
            html_content += f"""
                <tr>
                    <td class="{severity_class}">{vuln['severity']}</td>
                    <td>{vuln['type']}</td>
                    <td>{vuln['description']}</td>
                </tr>
            """
        
        html_content += "</table></div>"
    
    # Add informational section
    if scan_results.get('informational'):
        html_content += """
        <div class="section info">
            <h2>ℹ️ Informational Items</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Description</th>
                </tr>
        """
        
        for info in scan_results['informational']:
            html_content += f"""
                <tr>
                    <td>{info['type']}</td>
                    <td>{info['description']}</td>
                </tr>
            """
        
        html_content += "</table></div>"
    
    # Add raw output section
    html_content += f"""
        <div class="section">
            <h2>📄 Raw Nikto Output</h2>
            <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto;">{scan_results.get('raw_output', '')}</pre>
        </div>
        
        <div class="section">
            <p><em>Report generated by XKRed27 Security Suite - Nikto Scanner</em></p>
        </div>
    </body>
    </html>
    """
    
    return html_content

def show_nikto_interface():
    """Main Nikto web scanner interface"""
    st.header("🔍 Nikto Web Vulnerability Scanner")
    
    st.info("💡 **Nikto** is an Open Source web server scanner which performs comprehensive tests against web servers for multiple items, including dangerous files, outdated server software, and other security issues.")
    
    # System Performance Monitoring
    st.markdown("### 📊 System Performance Monitor")
    monitor = get_global_monitor()
    monitoring_container = st.container()
    create_monitoring_dashboard(monitor, monitoring_container)
    
    # Configuration section
    st.subheader("⚙️ Web Vulnerability Scan Configuration")
    
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
                key="nikto_host_selectbox"
            )
            
            # Auto-populate target field when selection changes
            if selected_host:
                selected_ip = extract_ip_from_selection(selected_host)
                st.session_state.nikto_target_from_discovery = selected_ip
                st.success(f"✅ Auto-populated target: {selected_ip}")
            
            st.markdown("#### ✍️ Target Configuration")
        else:
            st.markdown("#### ✍️ Target Configuration")
        
        # Target input modes
        target_mode = st.radio(
            "Target Input Mode:",
            ["URL", "IP Address", "IP:Port"],
            help="Choose how to specify the target",
            key="nikto_target_mode"
        )
        
        # Initialize target input with discovered host if selected
        initial_target = ""
        if 'nikto_target_from_discovery' in st.session_state:
            initial_target = st.session_state.nikto_target_from_discovery
        
        # Initialize target input value in session state if not exists
        if "nikto_target_input" not in st.session_state:
            st.session_state.nikto_target_input = initial_target
        elif initial_target:  # Update if we have a new target from discovery
            st.session_state.nikto_target_input = initial_target
        
        if target_mode == "URL":
            target_input = st.text_input(
                "Target URL",
                value=st.session_state.nikto_target_input if st.session_state.nikto_target_input.startswith('http') else "",
                placeholder="https://example.com or http://192.168.1.100",
                help="Enter the full URL including protocol (http:// or https://)",
                key="nikto_url_input"
            )
        elif target_mode == "IP Address":
            target_input = st.text_input(
                "Target IP Address",
                value=st.session_state.nikto_target_input if not st.session_state.nikto_target_input.startswith('http') else "",
                placeholder="192.168.1.100",
                help="Enter IP address (will scan port 80 by default)",
                key="nikto_ip_input"
            )
        else:  # IP:Port
            target_input = st.text_input(
                "Target IP:Port",
                value=st.session_state.nikto_target_input if ':' in st.session_state.nikto_target_input else "",
                placeholder="192.168.1.100:8080",
                help="Enter IP address and port separated by colon",
                key="nikto_ip_port_input"
            )
        
        # Clear the discovery target after use
        if 'nikto_target_from_discovery' in st.session_state:
            del st.session_state.nikto_target_from_discovery
    
    with col2:
        # Protocol and port options
        st.markdown("### 🔌 Connection Options")
        
        if target_mode == "URL":
            st.info("Protocol and port determined by URL")
        else:
            use_ssl = st.checkbox("Use SSL/HTTPS", help="Use HTTPS instead of HTTP")
            if target_mode == "IP Address":
                port = st.number_input("Port", min_value=1, max_value=65535, value=443 if use_ssl else 80)
    
    # Advanced options
    st.markdown("### ⚙️ Advanced Scan Options")
    
    # Create columns for advanced options
    col_adv1, col_adv2, col_adv3 = st.columns(3)
    
    with col_adv1:
        st.markdown("**Scan Intensity**")
        scan_tuning = st.multiselect(
            "Scan Tuning",
            [
                "1 - Interesting File / Seen in logs",
                "2 - Misconfiguration / Default File", 
                "3 - Information Disclosure",
                "4 - Injection (XSS/Script/HTML)",
                "5 - Remote File Retrieval - Inside Web Root",
                "6 - Denial of Service",
                "7 - Remote File Retrieval - Server Wide",
                "8 - Command Execution / Remote Shell",
                "9 - SQL Injection",
                "a - Authentication Bypass",
                "b - Software Identification",
                "c - Remote Source Inclusion",
                "x - Reverse Tuning Options (i.e., include all except specified)"
            ],
            default=["1 - Interesting File / Seen in logs", "2 - Misconfiguration / Default File", "3 - Information Disclosure"],
            help="Select types of tests to perform"
        )
        
        # Note: We capture standard text output and format it in our interface
        st.info("💡 Results will be captured as text and formatted in the interface")
    
    with col_adv2:
        st.markdown("**Performance**")
        timeout = st.slider("Timeout (seconds)", min_value=1, max_value=300, value=10, help="Request timeout")
        max_time = st.slider("Max Scan Time (minutes)", min_value=1, max_value=120, value=30, help="Maximum scan duration")
        
        follow_redirects = st.checkbox("Follow Redirects", value=True, help="Follow HTTP redirects")
        no_404_checks = st.checkbox("Skip 404 Checks", help="Don't check for 404 pages")
    
    with col_adv3:
        st.markdown("**Authentication**")
        use_auth = st.checkbox("Use Authentication", help="Use HTTP authentication")
        
        if use_auth:
            auth_username = st.text_input("Username", help="HTTP authentication username")
            auth_password = st.text_input("Password", type="password", help="HTTP authentication password")
        
        use_cookies = st.checkbox("Use Cookies", help="Use cookies from file")
        if use_cookies:
            cookie_jar = st.text_input("Cookie String", help="Cookie string or jar file path")
    
    # Scan configuration display
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
            valid_target = validate_ip_port(final_target)
            if valid_target:
                protocol = "https" if use_ssl else "http"
                final_target = f"{protocol}://{final_target}:{port}"
            else:
                st.error("❌ Invalid IP address format")
        else:  # IP:Port
            if ':' in final_target:
                ip, port_str = final_target.split(':', 1)
                try:
                    port_num = int(port_str)
                    valid_target = validate_ip_port(ip, port_num)
                    if valid_target:
                        protocol = "https" if use_ssl else "http"
                        final_target = f"{protocol}://{ip}:{port_num}"
                    else:
                        st.error("❌ Invalid IP address or port")
                except ValueError:
                    st.error("❌ Invalid port number")
            else:
                st.error("❌ Please use IP:Port format (e.g., 192.168.1.100:8080)")
        
        if valid_target:
            st.write(f"**Target:** {final_target}")
            if scan_tuning:
                tuning_codes = [option.split(' - ')[0] for option in scan_tuning]
                st.write(f"**Scan Types:** {', '.join(tuning_codes)}")
            st.write(f"**Timeout:** {timeout}s, **Max Time:** {max_time}m")
    else:
        st.info("📝 Please enter a target above to see scan configuration.")
    
    # Start scan button
    if st.button("🚀 Start Web Vulnerability Scan", type="primary", use_container_width=True, key="nikto_start_scan_btn"):
        if not target_input or not target_input.strip():
            st.error("❌ Please enter a target URL, IP address, or IP:Port")
        else:
            # Validate and build command
            valid_target = False
            final_target = target_input.strip()
            
            # Validate based on target mode
            if target_mode == "URL":
                valid_target = validate_url(final_target)
            elif target_mode == "IP Address":
                valid_target = validate_ip_port(final_target)
                if valid_target:
                    protocol = "https" if use_ssl else "http"
                    final_target = f"{protocol}://{final_target}:{port}"
            else:  # IP:Port
                if ':' in final_target:
                    ip, port_str = final_target.split(':', 1)
                    try:
                        port_num = int(port_str)
                        valid_target = validate_ip_port(ip, port_num)
                        if valid_target:
                            protocol = "https" if use_ssl else "http"
                            final_target = f"{protocol}://{ip}:{port_num}"
                    except ValueError:
                        valid_target = False
            
            if not valid_target:
                st.error("❌ Invalid target format. Please check your input.")
            else:
                # Build Nikto command
                cmd = ["nikto", "-h", final_target]
                
                # Add scan tuning options
                if scan_tuning:
                    tuning_codes = [option.split(' - ')[0] for option in scan_tuning]
                    cmd.extend(["-Tuning", "".join(tuning_codes)])
                
                # Note: We'll capture standard text output and format it in our interface
                # Adding -Format without -o (output file) causes an error, so we skip it
                
                # Add timeout
                cmd.extend(["-timeout", str(timeout)])
                
                # Add max time
                cmd.extend(["-maxtime", str(max_time * 60)])  # Convert minutes to seconds
                
                # Add other options
                if not follow_redirects:
                    cmd.append("-nointeractive")
                
                if no_404_checks:
                    cmd.append("-no404")
                
                # Add authentication
                if use_auth and auth_username:
                    if auth_password:
                        cmd.extend(["-id", f"{auth_username}:{auth_password}"])
                    else:
                        cmd.extend(["-id", auth_username])
                
                # Add cookies
                if use_cookies and cookie_jar:
                    cmd.extend(["-Cookies", cookie_jar])
                
                st.write(f"**Command:** `{' '.join(cmd)}`")
                
                # Warning about web scanning
                st.warning("⚠️ **Warning:** Web vulnerability scanning may trigger security systems and generate logs. Use only on authorized systems!")
                
                # Progress indicators
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Run scan
                with st.spinner("Starting Nikto web vulnerability scan..."):
                    output, error, return_code = run_nikto_scan(cmd, progress_bar, status_text)
                
                if return_code == 0 or output:  # Nikto might return non-zero even on success
                    st.success("✅ Web vulnerability scan completed!")
                    
                    # Add clear results button
                    col_clear1, col_clear2 = st.columns([1, 4])
                    with col_clear1:
                        if st.button("🔄 Clear & New Scan", help="Clear results and start a new scan", key="nikto_clear_new_scan_btn"):
                            # Clear session state
                            if 'last_nikto_results' in st.session_state:
                                del st.session_state['last_nikto_results']
                            if 'last_nikto_command' in st.session_state:
                                del st.session_state['last_nikto_command']
                            st.rerun()
                    
                    # Parse and display results
                    scan_results = parse_nikto_output(output)
                    
                    # Store results in session state for download
                    st.session_state['last_nikto_results'] = scan_results
                    st.session_state['last_nikto_command'] = ' '.join(cmd)
                    
                    # Display results
                    st.subheader("📊 Scan Results")
                    
                    # Summary metrics
                    col_metric1, col_metric2, col_metric3, col_metric4 = st.columns(4)
                    with col_metric1:
                        st.metric("Vulnerabilities", len(scan_results.get('vulnerabilities', [])))
                    with col_metric2:
                        st.metric("Informational", len(scan_results.get('informational', [])))
                    with col_metric3:
                        st.metric("Items Checked", scan_results.get('total_items_checked', 0))
                    with col_metric4:
                        st.metric("Target", scan_results.get('target', 'N/A'))
                    
                    # Vulnerabilities section
                    if scan_results.get('vulnerabilities'):
                        st.subheader("🚨 Vulnerabilities and Security Issues")
                        
                        # Create DataFrame for vulnerabilities
                        vuln_data = []
                        for vuln in scan_results['vulnerabilities']:
                            vuln_data.append({
                                'Severity': vuln['severity'],
                                'Type': vuln['type'],
                                'Description': vuln['description']
                            })
                        
                        if vuln_data:
                            df_vulns = pd.DataFrame(vuln_data)
                            st.dataframe(df_vulns, use_container_width=True)
                    
                    # Informational section
                    if scan_results.get('informational'):
                        with st.expander("ℹ️ Informational Items", expanded=False):
                            info_data = []
                            for info in scan_results['informational']:
                                info_data.append({
                                    'Type': info['type'],
                                    'Description': info['description']
                                })
                            
                            if info_data:
                                df_info = pd.DataFrame(info_data)
                                st.dataframe(df_info, use_container_width=True)
                    
                    # Raw output section
                    with st.expander("📄 Raw Nikto Output", expanded=False):
                        st.code(output, language="text")
                    
                    # Download section
                    st.subheader("💾 Download Results")
                    
                    col_download1, col_download2, col_download3 = st.columns(3)
                    
                    with col_download1:
                        # HTML Report
                        html_report = create_nikto_html_report(scan_results, ' '.join(cmd))
                        st.download_button(
                            label="📄 Download HTML Report",
                            data=html_report,
                            file_name=f"nikto_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                            mime="text/html"
                        )
                    
                    with col_download2:
                        # JSON Results
                        json_results = json.dumps(scan_results, indent=2, default=str)
                        st.download_button(
                            label="📊 Download JSON Results",
                            data=json_results,
                            file_name=f"nikto_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json"
                        )
                    
                    with col_download3:
                        # Raw Output
                        st.download_button(
                            label="📝 Download Raw Output",
                            data=output,
                            file_name=f"nikto_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                            mime="text/plain"
                        )
                
                else:
                    st.error("❌ Nikto scan failed!")
                    
                    col_error_clear1, col_error_clear2 = st.columns([1, 4])
                    with col_error_clear1:
                        if st.button("🔄 Try New Scan", help="Clear and try a different scan", key="nikto_try_new_scan_btn"):
                            st.rerun()
                    
                    if error:
                        st.error(f"**Error:** {error}")
                    
                    if output:
                        st.subheader("📄 Partial Output")
                        st.code(output, language="text")

if __name__ == "__main__":
    show_nikto_interface()
