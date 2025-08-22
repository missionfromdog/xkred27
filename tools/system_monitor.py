#!/usr/bin/env python3
"""
System Monitor Module for Nmap UI Suite
Provides real-time CPU, memory, and network monitoring capabilities
"""

import psutil
import time
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import streamlit as st

@dataclass
class SystemMetrics:
    """Data class for system metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    network_packets_sent: int
    network_packets_recv: int
    disk_usage_percent: float
    active_connections: int

class SystemMonitor:
    """Real-time system monitoring class"""
    
    def __init__(self, max_history: int = 60):
        """
        Initialize system monitor
        
        Args:
            max_history: Maximum number of data points to keep in history
        """
        self.max_history = max_history
        self.metrics_history: List[SystemMetrics] = []
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        
        # Network baseline for bandwidth calculation
        self.baseline_network: Optional[Dict] = None
        self.last_network_check = None
    
    def get_current_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_gb = memory.used / (1024**3)
        memory_total_gb = memory.total / (1024**3)
        
        # Network usage
        network = psutil.net_io_counters()
        
        # Disk usage (root partition)
        disk = psutil.disk_usage('/')
        disk_usage_percent = disk.percent
        
        # Active network connections
        try:
            connections = len(psutil.net_connections())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            connections = 0
        
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_used_gb=memory_used_gb,
            memory_total_gb=memory_total_gb,
            network_bytes_sent=network.bytes_sent,
            network_bytes_recv=network.bytes_recv,
            network_packets_sent=network.packets_sent,
            network_packets_recv=network.packets_recv,
            disk_usage_percent=disk_usage_percent,
            active_connections=connections
        )
    
    def calculate_bandwidth(self, current_metrics: SystemMetrics) -> Tuple[float, float]:
        """
        Calculate current bandwidth usage in MB/s
        
        Returns:
            Tuple of (upload_mbps, download_mbps)
        """
        if not self.baseline_network or not self.last_network_check:
            self.baseline_network = {
                'bytes_sent': current_metrics.network_bytes_sent,
                'bytes_recv': current_metrics.network_bytes_recv
            }
            self.last_network_check = current_metrics.timestamp
            return 0.0, 0.0
        
        # Calculate time difference
        time_diff = (current_metrics.timestamp - self.last_network_check).total_seconds()
        if time_diff <= 0:
            return 0.0, 0.0
        
        # Calculate bytes transferred
        bytes_sent_diff = current_metrics.network_bytes_sent - self.baseline_network['bytes_sent']
        bytes_recv_diff = current_metrics.network_bytes_recv - self.baseline_network['bytes_recv']
        
        # Convert to MB/s
        upload_mbps = (bytes_sent_diff / time_diff) / (1024**2)
        download_mbps = (bytes_recv_diff / time_diff) / (1024**2)
        
        # Update baseline
        self.baseline_network = {
            'bytes_sent': current_metrics.network_bytes_sent,
            'bytes_recv': current_metrics.network_bytes_recv
        }
        self.last_network_check = current_metrics.timestamp
        
        return max(0, upload_mbps), max(0, download_mbps)
    
    def start_monitoring(self, interval: float = 1.0):
        """
        Start continuous monitoring
        
        Args:
            interval: Monitoring interval in seconds
        """
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
    
    def _monitor_loop(self, interval: float):
        """Main monitoring loop (runs in separate thread)"""
        while self.monitoring:
            try:
                metrics = self.get_current_metrics()
                
                with self.lock:
                    self.metrics_history.append(metrics)
                    
                    # Limit history size
                    if len(self.metrics_history) > self.max_history:
                        self.metrics_history.pop(0)
                
                time.sleep(interval)
                
            except Exception as e:
                # Continue monitoring even if individual readings fail
                time.sleep(interval)
    
    def get_latest_metrics(self) -> Optional[SystemMetrics]:
        """Get the most recent metrics"""
        with self.lock:
            if self.metrics_history:
                return self.metrics_history[-1]
        return None
    
    def get_metrics_history(self, minutes: int = 5) -> List[SystemMetrics]:
        """
        Get metrics history for the last N minutes
        
        Args:
            minutes: Number of minutes of history to return
        """
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        with self.lock:
            return [
                metric for metric in self.metrics_history
                if metric.timestamp >= cutoff_time
            ]
    
    def get_performance_recommendations(self, current_metrics: SystemMetrics) -> List[str]:
        """
        Get performance recommendations based on current metrics
        
        Args:
            current_metrics: Current system metrics
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        # CPU recommendations
        if current_metrics.cpu_percent > 90:
            recommendations.append("🔴 **High CPU Usage (>90%)**: Consider reducing thread count")
        elif current_metrics.cpu_percent > 70:
            recommendations.append("🟡 **Moderate CPU Usage (>70%)**: Monitor performance, consider reducing threads if unstable")
        elif current_metrics.cpu_percent < 30:
            recommendations.append("🟢 **Low CPU Usage (<30%)**: You can likely increase thread count for faster scanning")
        
        # Memory recommendations
        if current_metrics.memory_percent > 90:
            recommendations.append("🔴 **High Memory Usage (>90%)**: System may become unstable, consider smaller wordlists")
        elif current_metrics.memory_percent > 70:
            recommendations.append("🟡 **Moderate Memory Usage (>70%)**: Monitor memory usage with large wordlists")
        
        # Disk recommendations
        if current_metrics.disk_usage_percent > 95:
            recommendations.append("🔴 **Very Low Disk Space (<5% free)**: Clean up disk space before running large scans")
        elif current_metrics.disk_usage_percent > 85:
            recommendations.append("🟡 **Low Disk Space (<15% free)**: Monitor disk usage during scans")
        
        # Connection recommendations
        if current_metrics.active_connections > 1000:
            recommendations.append("🟡 **High Connection Count (>1000)**: Monitor for connection limits")
        
        # General recommendations based on overall system load
        overall_load = (current_metrics.cpu_percent + current_metrics.memory_percent) / 2
        if overall_load < 40:
            recommendations.append("🟢 **System Load Low**: Optimal conditions for high-performance scanning")
        elif overall_load > 80:
            recommendations.append("🔴 **System Load High**: Consider reducing scan intensity")
        
        return recommendations if recommendations else ["🟢 **System Performance Good**: No specific recommendations"]

def create_monitoring_dashboard(monitor: SystemMonitor, container):
    """
    Create a Streamlit monitoring dashboard
    
    Args:
        monitor: SystemMonitor instance
        container: Streamlit container to render in
    """
    current_metrics = monitor.get_latest_metrics()
    if not current_metrics:
        container.info("📊 Starting system monitoring...")
        return
    
    # Calculate bandwidth
    upload_mbps, download_mbps = monitor.calculate_bandwidth(current_metrics)
    
    with container:
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="🖥️ CPU Usage",
                value=f"{current_metrics.cpu_percent:.1f}%",
                delta=None
            )
        
        with col2:
            st.metric(
                label="🧠 Memory Usage",
                value=f"{current_metrics.memory_percent:.1f}%",
                delta=f"{current_metrics.memory_used_gb:.1f}GB / {current_metrics.memory_total_gb:.1f}GB"
            )
        
        with col3:
            st.metric(
                label="📡 Upload",
                value=f"{upload_mbps:.2f} MB/s",
                delta=None
            )
        
        with col4:
            st.metric(
                label="📥 Download", 
                value=f"{download_mbps:.2f} MB/s",
                delta=None
            )
        
        # Additional metrics row
        col5, col6, col7, col8 = st.columns(4)
        
        with col5:
            st.metric(
                label="💾 Disk Usage",
                value=f"{current_metrics.disk_usage_percent:.1f}%",
                delta=None
            )
        
        with col6:
            st.metric(
                label="🔗 Connections",
                value=str(current_metrics.active_connections),
                delta=None
            )
        
        with col7:
            st.metric(
                label="📦 Network Out",
                value=f"{current_metrics.network_packets_sent:,}",
                delta="packets"
            )
        
        with col8:
            st.metric(
                label="📦 Network In",
                value=f"{current_metrics.network_packets_recv:,}",
                delta="packets"
            )
        
        # Performance recommendations
        recommendations = monitor.get_performance_recommendations(current_metrics)
        
        st.subheader("💡 Performance Recommendations")
        for recommendation in recommendations:
            st.write(recommendation)

def get_optimal_thread_count() -> Dict[str, int]:
    """
    Calculate optimal thread counts based on current system resources
    
    Returns:
        Dictionary with recommended thread counts for different scenarios
    """
    cpu_count = psutil.cpu_count(logical=True)
    memory_gb = psutil.virtual_memory().total / (1024**3)
    
    # Base calculations
    conservative = max(5, cpu_count)
    moderate = max(10, cpu_count * 2)
    aggressive = max(20, cpu_count * 4)
    
    # Adjust for memory
    if memory_gb < 4:
        # Low memory system
        conservative = min(conservative, 10)
        moderate = min(moderate, 20)
        aggressive = min(aggressive, 30)
    elif memory_gb > 16:
        # High memory system
        aggressive = min(aggressive * 2, 200)
    
    return {
        "conservative": conservative,
        "moderate": moderate,
        "aggressive": aggressive,
        "maximum": min(200, cpu_count * 8)  # Reasonable upper limit
    }

# Global monitor instance for the app
_global_monitor: Optional[SystemMonitor] = None

def get_global_monitor() -> SystemMonitor:
    """Get or create the global system monitor instance"""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = SystemMonitor()
        _global_monitor.start_monitoring()
    return _global_monitor

def cleanup_monitor():
    """Cleanup global monitor (call on app shutdown)"""
    global _global_monitor
    if _global_monitor:
        _global_monitor.stop_monitoring()
        _global_monitor = None
