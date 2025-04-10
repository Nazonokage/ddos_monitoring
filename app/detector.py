#!/usr/bin/env python3
import time
import psutil
import socket
import collections
import platform
from datetime import datetime
from threading import Lock, Thread, Event
import logging
from typing import Dict, List, Tuple, Deque

class DDoSDetector:
    def __init__(self, threshold=1000, window=10, alert_threshold=0.7, interval=1.0):
        """
        Enhanced DDoSDetector for Flask integration.
        
        Args:
            threshold: Max allowed connections before triggering critical alert
            window: Sliding time window in seconds for averages
            alert_threshold: Warning level (% of threshold) for moderate alerts
            interval: Sampling interval in seconds
        """
        self.threshold = threshold
        self.window = window
        self.alert_threshold = alert_threshold
        self.interval = interval

        # Data structures
        self.connection_history: Deque[int] = collections.deque(maxlen=window)
        self.bytes_history: Deque[int] = collections.deque(maxlen=window)
        self.alert_history: List[Dict] = []
        self.host_info = self._get_host_info()

        # Thread control
        self._monitor_thread = None
        self._stop_event = Event()
        self.data_lock = Lock()
        
        # Current state
        self.current_data = {
            'status': {'text': 'Not running', 'color': 'secondary'},
            'connections': 0,
            'traffic_rate': 0,
            'top_processes': [],
            'alerts': [],
            'history': {
                'connections': [],
                'traffic': [],
                'labels': []
            },
            'system_stats': {
                'cpu': 0,
                'memory': 0,
                'network': {'sent': 0, 'recv': 0}
            },
            'settings': {
                'threshold': threshold,
                'alert_threshold': alert_threshold,
                'interval': interval
            },
            'host_info': self.host_info
        }

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('DDoSDetector')

    def _get_host_info(self) -> Dict:
        """Get system host information."""
        return {
            'hostname': socket.gethostname(),
            'os': f"{platform.system()} {platform.release()}",
            'ip': socket.gethostbyname(socket.gethostname()),
            'cpu_count': psutil.cpu_count(),
            'memory': round(psutil.virtual_memory().total / (1024**3), 2)
        }

    def get_connections(self) -> Tuple[int, Dict[str, int]]:
        """Get active connections with process details."""
        total = 0
        by_proc = {}
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status in ('ESTABLISHED', 'SYN_SENT') and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    by_proc[proc_name] = by_proc.get(proc_name, 0) + 1
                    total += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        return total, by_proc

    def get_network_traffic(self) -> Tuple[int, int]:
        """Get network traffic stats in bytes."""
        io = psutil.net_io_counters()
        return io.bytes_sent, io.bytes_recv

    def get_system_stats(self) -> Dict:
        """Get current system resource usage."""
        return {
            'cpu': psutil.cpu_percent(),
            'memory': psutil.virtual_memory().percent,
            'network': {
                'sent': psutil.net_io_counters().bytes_sent,
                'recv': psutil.net_io_counters().bytes_recv
            }
        }

    def establish_baseline(self, duration=60) -> None:
        """Establish baseline network activity."""
        self.logger.info(f"Establishing baseline for {duration} seconds...")
        
        conn_samples = []
        byte_samples = []
        start = time.time()

        while time.time() - start < duration and not self._stop_event.is_set():
            try:
                connections, _ = self.get_connections()
                sent, recv = self.get_network_traffic()
                
                conn_samples.append(connections)
                byte_samples.append(sent + recv)
                
                # Update the current data during baseline
                with self.data_lock:
                    self.current_data['connections'] = connections
                    self.current_data['traffic_rate'] = (sent + recv) / 1024
                    self.current_data['system_stats'] = {
                        'cpu': psutil.cpu_percent(),
                        'memory': psutil.virtual_memory().percent,
                        'network': {'sent': sent, 'recv': recv}
                    }
                
                time.sleep(self.interval)
            except Exception as e:
                self.logger.error(f"Baseline error: {e}")
                break

        if conn_samples:
            self.baseline_connections = sum(conn_samples) / len(conn_samples)
            self.baseline_bytes = sum(byte_samples) / len(byte_samples)
            
            self.logger.info(
                f"Baseline established - Connections: {self.baseline_connections:.2f}, "
                f"Traffic: {self.baseline_bytes / 1024:.2f} KB"
            )

    def start_monitoring(self) -> None:
        """Start the monitoring thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self.logger.warning("Monitoring already running")
            return

        self._stop_event.clear()
        self._monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        with self.data_lock:
            self.current_data['status'] = {'text': 'Monitoring started', 'color': 'info'}
        
        self.logger.info("Monitoring started")

    def stop_monitoring(self) -> None:
        """Stop the monitoring thread."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
        
        with self.data_lock:
            self.current_data['status'] = {'text': 'Monitoring stopped', 'color': 'secondary'}
        
        self.logger.info("Monitoring stopped")

    def _monitor_loop(self) -> None:
        """Main monitoring loop running in background thread."""
        # Establish baseline if not done
        if not hasattr(self, 'baseline_connections'):
            self.establish_baseline()

        prev_sent, prev_recv = self.get_network_traffic()

        while not self._stop_event.is_set():
            try:
                timestamp = datetime.now()
                connections, by_proc = self.get_connections()
                curr_sent, curr_recv = self.get_network_traffic()
                
                # Calculate deltas
                delta_sent = curr_sent - prev_sent
                delta_recv = curr_recv - prev_recv
                delta_total = delta_sent + delta_recv
                
                # Update history
                self.connection_history.append(connections)
                self.bytes_history.append(delta_total)
                
                # Calculate averages
                avg_conns = sum(self.connection_history) / len(self.connection_history) if self.connection_history else 0
                avg_bytes = sum(self.bytes_history) / len(self.bytes_history) if self.bytes_history else 0
                
                # Check for alerts
                self._check_alerts(
                    connections, 
                    avg_conns, 
                    delta_total, 
                    avg_bytes,
                    timestamp
                )
                
                # Update current data
                with self.data_lock:
                    self.current_data.update({
                        'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        'status': self._get_status(connections),
                        'connections': connections,
                        'traffic_rate': delta_total / 1024,  # in KB
                        'traffic_breakdown': {
                            'sent': delta_sent,
                            'received': delta_recv
                        },
                        'top_processes': sorted(by_proc.items(), key=lambda x: x[1], reverse=True)[:5],
                        'system_stats': self.get_system_stats(),
                        'history': self._update_history(connections, delta_total)
                    })
                
                prev_sent, prev_recv = curr_sent, curr_recv
                time.sleep(self.interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                time.sleep(5)  # Wait before retrying

    def _update_history(self, conns: int, bytes: int) -> Dict:
        """Maintain historical data for charts."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Keep last 60 data points
        history = self.current_data['history']
        if len(history['connections']) >= 60:
            history['connections'].pop(0)
            history['traffic'].pop(0)
            history['labels'].pop(0)
            
        history['connections'].append(conns)
        history['traffic'].append(bytes / 1024)  # KB
        history['labels'].append(timestamp)
        
        return history

    def _check_alerts(self, conns: int, avg_conns: float, 
                     delta_bytes: int, avg_bytes: float,
                     timestamp: datetime) -> None:
        """Check conditions and generate alerts."""
        alerts = []
        
        # Connection threshold alert
        if conns > self.threshold:
            alerts.append({
                'type': 'CRITICAL',
                'message': f"Connection count ({conns}) exceeded threshold ({self.threshold})",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        
        # Connection spike alert
        if (len(self.connection_history) >= 3 and 
            conns > 2 * avg_conns and 
            conns > 50):
            alerts.append({
                'type': 'WARNING',
                'message': f"Connection spike! Current: {conns}, Avg: {avg_conns:.2f}",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        
        # Traffic spike alert
        if (delta_bytes > 5 * self.baseline_bytes and 
            delta_bytes > 1_000_000):
            alerts.append({
                'type': 'WARNING',
                'message': f"High traffic! {delta_bytes / 1024 / 1024:.2f} MB/s",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        
        # Add new alerts to history
        if alerts:
            self.alert_history.extend(alerts)
            for alert in alerts:
                self.logger.warning(f"{alert['type']}: {alert['message']}")
            
            with self.data_lock:
                self.current_data['alerts'] = self.alert_history[-5:]  # Keep last 5 alerts

    def _get_status(self, conns: int) -> Dict:
        """Get current system status with color coding."""
        usage = conns / self.threshold
        if usage >= 1.0:
            return {'text': 'CRITICAL: Potential DDoS/DoS attack!', 'color': 'danger'}
        elif usage >= self.alert_threshold:
            return {'text': 'WARNING: Suspicious traffic level', 'color': 'warning'}
        return {'text': 'OK: Normal traffic', 'color': 'success'}

    def get_status_data(self) -> Dict:
        """Get current monitoring data for API."""
        with self.data_lock:
            return self.current_data