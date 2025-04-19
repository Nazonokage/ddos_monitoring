## version 2
import time
import psutil
import socket
import platform
from datetime import datetime
from threading import Lock, Thread, Event
import logging
from typing import Dict, List, Tuple, Deque, Optional, DefaultDict
from collections import deque, defaultdict
from .ml_detector import MLDDoSDetector

class DDoSDetector:
    def __init__(self, threshold: int = 1000, window: int = 10, 
                 alert_threshold: float = 0.7, interval: float = 1.0):
        self.threshold = threshold
        self.window = window
        self.alert_threshold = alert_threshold
        self.interval = interval

        # Data structures
        self.connection_history = deque(maxlen=window)
        self.bytes_history = deque(maxlen=window)
        self.alert_history: List[Dict] = []
        
        # Enhanced traffic tracking with direction awareness
        self.traffic_stats = {
            'inbound': 0,       # Bytes received
            'outbound': 0,      # Bytes sent
            'inbound_conn': 0,  # Inbound connection count
            'outbound_conn': 0, # Outbound connection count
            'top_source_ips': defaultdict(int),
            'top_dest_ips': defaultdict(int),
            'top_apps': defaultdict(lambda: {'in': 0, 'out': 0}),
            'ports': defaultdict(lambda: {'in': 0, 'out': 0}),
            'connection_types': defaultdict(int)
        }
        
        # System info
        self.host_info = self._get_host_info()
        self.baseline_connections = 0
        self.baseline_bytes = 0
        
        # ML Integration
        self.ml_detector = MLDDoSDetector()
        self.anomaly_scores = deque(maxlen=10)

        # Thread control
        self._monitor_thread: Optional[Thread] = None
        self._stop_event = Event()
        self.data_lock = Lock()
        
        # Current state
        self.current_data = {
            'status': {'text': 'Not running', 'color': 'secondary'},
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'connections': 0,
            'traffic': {
                'rate': 0,          # KB/s
                'inbound': 0,       # Bytes
                'outbound': 0,     # Bytes
                'direction_ratio': 0,
                'top_source_ips': [],
                'top_dest_ips': [],
                'top_ports': [],
                'top_apps': [],
                'connection_types': {}
            },
            'system': {
                'cpu': 0,
                'cpu_cores': [],
                'memory': 0,
                'network': {'sent': 0, 'recv': 0},
                'temperatures': {}
            },
            'history': {
                'connections': [],
                'traffic': [],
                'labels': []
            },
            'alerts': [],
            'settings': {
                'threshold': threshold,
                'alert_threshold': alert_threshold,
                'interval': interval
            },
            'host_info': self.host_info,
            'ml_stats': {
                'anomaly_score': 0,
                'avg_anomaly': 0
            }
        }

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('DDoSDetector')

    def _get_host_info(self) -> Dict:
        """Get comprehensive host information."""
        interfaces = psutil.net_if_addrs()
        ip_addresses = []
        for iface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip_addresses.append(f"{iface}: {addr.address}")

        return {
            'hostname': socket.gethostname(),
            'os': f"{platform.system()} {platform.release()}",
            'ips': ip_addresses,
            'cpu_count': psutil.cpu_count(),
            'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        }

    def get_connections(self) -> Tuple[int, Dict[str, Dict[str, int]]]:
        """Get active connections with direction awareness."""
        total = 0
        by_proc = defaultdict(lambda: {'in': 0, 'out': 0})
        
        # Reset connection counters
        self.traffic_stats['inbound_conn'] = 0
        self.traffic_stats['outbound_conn'] = 0
        for key in ['top_source_ips', 'top_dest_ips', 'connection_types']:
            self.traffic_stats[key].clear()

        for conn in psutil.net_connections(kind='inet'):
            direction = None  # Initialize direction
            try:
                # Track connection status types
                self.traffic_stats['connection_types'][conn.status] += 1
                
                # Only count active connections
                if conn.status not in ('ESTABLISHED', 'SYN_SENT', 'SYN_RECV'):
                    continue

                # Track direction - FIXED LOGIC
                if conn.raddr and conn.raddr != ():  # Proper inbound check
                    self.traffic_stats['inbound_conn'] += 1
                    if conn.raddr.ip:  # Add existence check
                        self.traffic_stats['top_source_ips'][conn.raddr.ip] += 1
                    direction = 'in'
                elif conn.laddr and conn.laddr != ():  # Proper outbound check
                    self.traffic_stats['outbound_conn'] += 1
                    if conn.laddr.ip:  # Add existence check
                        self.traffic_stats['top_dest_ips'][conn.laddr.ip] += 1
                    direction = 'out'

                # Only track if direction was determined
                if direction and conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        by_proc[proc_name][direction] += 1
                        if conn.laddr:  # Only track ports for outbound
                            self.traffic_stats['ports'][conn.laddr.port][direction] += 1
                        total += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
            except Exception as e:
                self.logger.error(f"Connection processing error: {e}", exc_info=True)
                continue
                
        return total, by_proc

    def _update_traffic_stats(self, sent: int, recv: int):
        """Update traffic statistics with direction awareness."""
        self.traffic_stats.update({
            'inbound': recv,
            'outbound': sent,
            'direction_ratio': recv / (sent + 1e-6)  # Avoid division by zero
        })
        
        with self.data_lock:
            # Prepare top apps with direction info
            top_apps = sorted(
                [(k, v['in'], v['out']) for k, v in self.traffic_stats['top_apps'].items()],
                key=lambda x: x[1] + x[2], 
                reverse=True
            )[:5]
            
            # Prepare top ports with direction info
            top_ports = sorted(
                [(k, v['in'], v['out']) for k, v in self.traffic_stats['ports'].items()],
                key=lambda x: x[1] + x[2],
                reverse=True
            )[:5]

            self.current_data['traffic'].update({
                'inbound': recv,
                'outbound': sent,
                'direction_ratio': self.traffic_stats['direction_ratio'],
                'top_source_ips': sorted(
                    self.traffic_stats['top_source_ips'].items(),
                    key=lambda x: x[1], reverse=True)[:5],
                'top_dest_ips': sorted(
                    self.traffic_stats['top_dest_ips'].items(),
                    key=lambda x: x[1], reverse=True)[:5],
                'top_ports': top_ports,
                'top_apps': top_apps,
                'connection_types': dict(self.traffic_stats['connection_types'])
            })

    def get_system_stats(self) -> Dict:
        """Get comprehensive system resource usage."""
        cpu_percent = psutil.cpu_percent(percpu=True)
        mem = psutil.virtual_memory()
        
        return {
            'cpu': sum(cpu_percent)/len(cpu_percent),  # Average
            'cpu_cores': cpu_percent,                   # Per core
            'memory': mem.percent,
            'network': {
                'sent': psutil.net_io_counters().bytes_sent,
                'recv': psutil.net_io_counters().bytes_recv
            },
            'temperatures': psutil.sensors_temperatures() if hasattr(psutil, 'sensors_temperatures') else {}
        }

    def _monitor_loop(self):
        """Main monitoring loop with enhanced metrics."""
        if not hasattr(self, 'baseline_connections'):
            self.establish_baseline()

        prev_sent, prev_recv = self.get_network_traffic()

        while not self._stop_event.is_set():
            try:
                timestamp = datetime.now()
                connections, by_proc = self.get_connections()
                curr_sent, curr_recv = self.get_network_traffic()
                
                # Calculate traffic rates (bytes/second)
                delta_sent = curr_sent - prev_sent
                delta_recv = curr_recv - prev_recv
                traffic_rate = (delta_sent + delta_recv) / self.interval
                
                # Update traffic stats and direction-aware metrics
                self.traffic_stats['top_apps'] = by_proc
                self._update_traffic_stats(delta_sent, delta_recv)
                
                # Update history
                self.connection_history.append(connections)
                self.bytes_history.append(traffic_rate)
                
                # Check for alerts
                self._check_alerts(
                    connections, 
                    sum(self.connection_history)/len(self.connection_history),
                    traffic_rate,
                    sum(self.bytes_history)/len(self.bytes_history),
                    timestamp
                )
                
                # Update current data
                with self.data_lock:
                    self.current_data.update({
                        'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        'status': self._get_status(connections),
                        'connections': connections,
                        'traffic': {
                            'rate': traffic_rate / 1024,  # Convert to KB/s
                            **self.current_data['traffic']  # Keep existing traffic data
                        },
                        'top_processes': [
                            (k, v['in'], v['out']) 
                            for k, v in by_proc.items()
                        ][:5],
                        'system': self.get_system_stats(),
                        'history': self._update_history(connections, traffic_rate)
                    })
                
                prev_sent, prev_recv = curr_sent, curr_recv
                time.sleep(self.interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}", exc_info=True)
                time.sleep(5) 

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
        """Enhanced alert detection with traffic analysis."""
        alerts = []
        
        # ML Anomaly Detection
        ml_score = self.ml_detector.predict_anomaly({
            'connections': conns,
            'traffic_rate': delta_bytes / 1024,
            'system_stats': {
                'cpu': psutil.cpu_percent(),
                'memory': psutil.virtual_memory().percent
            }
        })
        self.anomaly_scores.append(ml_score)
        
        # Update ML stats
        with self.data_lock:
            self.current_data['ml_stats'] = {
                'anomaly_score': ml_score,
                'avg_anomaly': sum(self.anomaly_scores) / len(self.anomaly_scores) if self.anomaly_scores else 0
            }

        # ML-based alerts
        if ml_score > 0.85:
            alerts.append({
                'type': 'ML CRITICAL',
                'message': f"ML detected anomaly (score: {ml_score:.2f})",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })

        # Threshold-based alerts
        if conns > self.threshold:
            alerts.append({
                'type': 'CRITICAL',
                'message': f"Connections ({conns}) > threshold ({self.threshold})",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        
        # Connection spike detection
        if len(self.connection_history) >= 3 and conns > 2 * avg_conns and conns > 50:
            alerts.append({
                'type': 'WARNING',
                'message': f"Connection spike: {conns} (avg: {avg_conns:.1f})",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })

        # Traffic anomaly detection
        if delta_bytes > 5 * self.baseline_bytes and delta_bytes > 1_000_000:
            alerts.append({
                'type': 'WARNING',
                'message': f"High traffic: {delta_bytes/1024/1024:.2f} MB/s",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })

        # Traffic direction alerts
        traffic_stats = self.current_data['traffic']
        if traffic_stats.get('direction_ratio', 0) > 10:
            alerts.append({
                'type': 'WARNING',
                'message': f"High inbound/outbound ratio: {traffic_stats['direction_ratio']:.1f}",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })

        # Suspicious source IP detection
        if traffic_stats['top_source_ips']:
            top_source_count = traffic_stats['top_source_ips'][0][1] if traffic_stats['top_source_ips'] else 0
            if top_source_count > 50:
                alerts.append({
                    'type': 'WARNING',
                    'message': f"Suspicious source IP: {top_source_count} connections",
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
                })

        # Unusual port activity
        unusual_ports = [port for port, _, _ in traffic_stats['top_ports']  # Add second underscore
                        if port not in [80, 443, 22, 53]]
        if unusual_ports:
            alerts.append({
                'type': 'WARNING',
                'message': f"Unusual port activity: {unusual_ports}",
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })

        # Update alerts if any detected
        if alerts:
            self.alert_history.extend(alerts)
            for alert in alerts:
                self.logger.warning(f"{alert['type']}: {alert['message']}")
            
            with self.data_lock:
                self.current_data['alerts'] = self.alert_history[-5:]

    def _get_status(self, conns: int) -> Dict:
        """Get current system status with color coding, enhanced with ML info."""
        usage = conns / self.threshold
        
        # Check ML alerts first
        if self.anomaly_scores and max(self.anomaly_scores) > 0.9:
            return {'text': 'ML CRITICAL: Anomaly detected!', 'color': 'dark'}
            
        # Original status checks
        if usage >= 1.0:
            return {'text': 'CRITICAL: Potential DDoS/DoS attack!', 'color': 'danger'}
        elif usage >= self.alert_threshold:
            return {'text': 'WARNING: Suspicious traffic level', 'color': 'warning'}
        return {'text': 'OK: Normal traffic', 'color': 'success'}
    
    def update_settings(self, threshold: int, alert_threshold: float, interval: float):
        """Update monitoring settings dynamically."""
        self.threshold = threshold
        self.alert_threshold = alert_threshold
        self.interval = interval
        
        with self.data_lock:
            self.current_data['settings'].update({
                'threshold': threshold,
                'alert_threshold': alert_threshold,
                'interval': interval
            })
        self.logger.info(f"Updated settings: threshold={threshold}, alert={alert_threshold}, interval={interval}")

    def get_status_data(self) -> Dict:
        """Get current monitoring data for API."""
        with self.data_lock:
            return self.current_data
        
    # Add these methods to your DDoSDetector class in detector.py

    def establish_baseline(self, duration=60) -> None:
        """Establish baseline network activity."""
        self.logger.info(f"Establishing baseline for {duration} seconds...")
        
        conn_samples = []
        byte_samples = []
        start = time.time()

        while time.time() - start < duration and not self._stop_event.is_set():
            try:
                connections, _ = self.get_connections()
                sent, recv = psutil.net_io_counters().bytes_sent, psutil.net_io_counters().bytes_recv
                
                conn_samples.append(connections)
                byte_samples.append((sent + recv) / self.interval)  # ✅ Bytes per second (correct)
                
                with self.data_lock:
                    self.current_data['connections'] = connections
                    self.current_data['traffic']['rate'] = (sent + recv) / 1024
                    self.current_data['system'] = self.get_system_stats()
                
                time.sleep(self.interval)
            except Exception as e:
                self.logger.error(f"Baseline error: {e}")
                break

        if conn_samples:
            self.baseline_connections = sum(conn_samples) / len(conn_samples)
            self.baseline_bytes = sum(byte_samples) / len(byte_samples)
            self.logger.info(f"Baseline established - Connections: {self.baseline_connections:.2f}, Traffic: {self.baseline_bytes/1024:.2f} KB")

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

    def get_network_traffic(self) -> Tuple[int, int]:
        """Get network traffic stats."""
        io = psutil.net_io_counters()
        return io.bytes_sent, io.bytes_recv