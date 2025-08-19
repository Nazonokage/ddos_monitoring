#!/usr/bin/env python3
import time
import psutil
import socket
import collections
import platform
from datetime import datetime, timedelta
from threading import Lock, Thread, Event
import logging
from typing import Dict, List, Tuple, Deque, Optional
import statistics
import json

class EnhancedDDoSDetector:
    def __init__(self, threshold=500, window=10, alert_threshold=0.7, interval=1.0):
        """
        Enhanced DDoSDetector with improved alert system and attack pattern detection.
        
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

        # Enhanced data structures for better detection
        self.connection_history: Deque[int] = collections.deque(maxlen=window * 2)
        self.bytes_history: Deque[int] = collections.deque(maxlen=window * 2)
        self.packet_history: Deque[int] = collections.deque(maxlen=window * 2)
        self.alert_history: List[Dict] = []
        self.connection_details: Dict[str, Dict] = {}
        self.host_info = self._get_host_info()
        
        # Enhanced attack detection variables
        self.baseline_connections = 0
        self.baseline_bytes = 0
        self.baseline_packets = 0
        self.baseline_established = False
        self.last_network_stats = None
        self.suspicious_endpoints = {}
        self.attack_patterns = {
            'syn_flood': {'detected': False, 'count': 0, 'last_seen': None},
            'udp_flood': {'detected': False, 'count': 0, 'last_seen': None},
            'icmp_flood': {'detected': False, 'count': 0, 'last_seen': None},
            'connection_flood': {'detected': False, 'count': 0, 'last_seen': None},
            'traffic_flood': {'detected': False, 'count': 0, 'last_seen': None}  # NEW: Traffic flood pattern
        }
        
        # FIXED: Increased sensitivity for traffic spike detection
        self.spike_detection_sensitivity = 2.0  # Lowered from 3.0 to 2.0 (more sensitive)
        self.minimum_spike_threshold = 50  # Lowered from 100 to 50 KB (detects smaller spikes)
        self.traffic_flood_threshold = 5.0  # NEW: 5x baseline traffic = automatic flood detection
        
        # Thread control
        self._monitor_thread = None
        self._stop_event = Event()
        self.data_lock = Lock()
        
        # Current state
        self.current_data = {
            'status': {'text': 'Not running', 'color': 'secondary'},
            'connections': 0,
            'traffic_rate': 0,
            'packet_rate': 0,
            'top_processes': [],
            'top_endpoints': [],
            'suspicious_endpoints': [],
            'alerts': [],
            'attack_summary': {},
            'history': {
                'connections': [],
                'traffic': [],
                'packets': [],
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
            'host_info': self.host_info,
            'baseline_info': {
                'connections': 0,
                'traffic': 0,
                'packets': 0,
                'established': False
            }
        }

        # Configure logging with more detailed format
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('ddos_monitor.log', mode='a')
            ]
        )
        self.logger = logging.getLogger('EnhancedDDoSDetector')

    def _get_host_info(self) -> Dict:
        """Get system host information."""
        return {
            'hostname': socket.gethostname(),
            'os': f"{platform.system()} {platform.release()}",
            'ip': socket.gethostbyname(socket.gethostname()),
            'cpu_count': psutil.cpu_count(),
            'memory': round(psutil.virtual_memory().total / (1024**3), 2)
        }

    def get_enhanced_network_stats(self) -> Dict:
        """Get enhanced network statistics including packet counts"""
        try:
            io_stats = psutil.net_io_counters()
            interface_stats = psutil.net_io_counters(pernic=True)
            
            return {
                'bytes_sent': io_stats.bytes_sent,
                'bytes_recv': io_stats.bytes_recv,
                'packets_sent': io_stats.packets_sent,
                'packets_recv': io_stats.packets_recv,
                'errin': io_stats.errin,
                'errout': io_stats.errout,
                'dropin': io_stats.dropin,
                'dropout': io_stats.dropout,
                'interfaces': interface_stats
            }
        except Exception as e:
            self.logger.error(f"Error getting network stats: {e}")
            return {}

    def get_connections(self) -> Tuple[int, Dict[str, int], Dict[str, Dict]]:
        """Enhanced connection analysis with connection state tracking"""
        total = 0
        by_proc = {}
        by_endpoint = collections.defaultdict(lambda: {
            'count': 0,
            'ports': set(),
            'processes': set(),
            'states': collections.defaultdict(int),
            'first_seen': datetime.now(),
            'last_seen': datetime.now()
        })

        connection_states = {
            'ESTABLISHED': 0,
            'SYN_SENT': 0,
            'SYN_RECV': 0,
            'TIME_WAIT': 0,
            'CLOSE_WAIT': 0,
            'LISTEN': 0
        }

        for conn in psutil.net_connections(kind='inet'):
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    remote_addr = self._format_remote_addr(conn)
                    
                    if conn.status in connection_states:
                        connection_states[conn.status] += 1
                    
                    if conn.status in ('ESTABLISHED', 'SYN_SENT', 'SYN_RECV'):
                        by_proc[proc_name] = by_proc.get(proc_name, 0) + 1
                        total += 1

                        if remote_addr:
                            endpoint = by_endpoint[remote_addr]
                            endpoint['count'] += 1
                            endpoint['ports'].add(conn.laddr.port)
                            endpoint['processes'].add(proc_name)
                            endpoint['states'][conn.status] += 1
                            endpoint['last_seen'] = datetime.now()
                            
                            self._analyze_endpoint_behavior(remote_addr, conn, proc_name)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        formatted_endpoints = {}
        for addr, data in by_endpoint.items():
            formatted_endpoints[addr] = {
                'count': data['count'],
                'ports': list(data['ports']),
                'processes': list(data['processes']),
                'states': dict(data['states']),
                'first_seen': data['first_seen'].isoformat(),
                'last_seen': data['last_seen'].isoformat()
            }
        
        self.connection_states = connection_states
        
        return total, by_proc, formatted_endpoints

    def _analyze_endpoint_behavior(self, endpoint: str, conn, proc_name: str):
        """Analyze endpoint behavior for suspicious patterns"""
        current_time = datetime.now()
        
        if endpoint not in self.suspicious_endpoints:
            self.suspicious_endpoints[endpoint] = {
                'connection_count': 0,
                'ports_targeted': set(),
                'processes_involved': set(),
                'first_seen': current_time,
                'last_activity': current_time,
                'suspicious_score': 0,
                'flags': []
            }
        
        endpoint_data = self.suspicious_endpoints[endpoint]
        endpoint_data['connection_count'] += 1
        endpoint_data['ports_targeted'].add(conn.laddr.port)
        endpoint_data['processes_involved'].add(proc_name)
        endpoint_data['last_activity'] = current_time
        
        suspicious_score = 0
        flags = []
        
        if endpoint_data['connection_count'] > 20:  # Lowered threshold
            suspicious_score += 30
            flags.append(f"High connection count: {endpoint_data['connection_count']}")
        
        if len(endpoint_data['ports_targeted']) > 5:  # Lowered threshold
            suspicious_score += 25
            flags.append(f"Port scanning: {len(endpoint_data['ports_targeted'])} ports")
        
        time_window = current_time - endpoint_data['first_seen']
        if time_window.total_seconds() > 0:
            connection_rate = endpoint_data['connection_count'] / time_window.total_seconds()
            if connection_rate > 3:  # Lowered from 5 to 3 connections/sec
                suspicious_score += 40
                flags.append(f"Rapid connections: {connection_rate:.2f}/sec")
        
        if len(endpoint_data['processes_involved']) > 2:  # Lowered threshold
            suspicious_score += 20
            flags.append(f"Multiple processes: {len(endpoint_data['processes_involved'])}")
        
        endpoint_data['suspicious_score'] = suspicious_score
        endpoint_data['flags'] = flags
        
        if (current_time - endpoint_data['last_activity']).total_seconds() > 300 and suspicious_score < 15:  # Lowered threshold
            del self.suspicious_endpoints[endpoint]

    def _format_remote_addr(self, conn) -> Optional[str]:
        """Format remote address for consistent tracking."""
        if not conn.raddr:
            return None
            
        if ':' in conn.raddr.ip and '.' not in conn.raddr.ip:
            try:
                ip = socket.inet_pton(socket.AF_INET6, conn.raddr.ip)
                return socket.inet_ntop(socket.AF_INET6, ip) + f":{conn.raddr.port}"
            except:
                pass
        return f"{conn.raddr.ip}:{conn.raddr.port}"

    def establish_baseline(self, duration=60) -> None:
        """Establish baseline network activity with enhanced metrics"""
        self.logger.info(f"Establishing baseline for {duration} seconds...")
        
        conn_samples = []
        byte_samples = []
        packet_samples = []
        start = time.time()

        while time.time() - start < duration and not self._stop_event.is_set():
            try:
                connections, _, _ = self.get_connections()
                network_stats = self.get_enhanced_network_stats()
                
                conn_samples.append(connections)
                
                if network_stats:
                    total_bytes = network_stats['bytes_sent'] + network_stats['bytes_recv']
                    total_packets = network_stats['packets_sent'] + network_stats['packets_recv']
                    byte_samples.append(total_bytes)
                    packet_samples.append(total_packets)
                
                with self.data_lock:
                    self.current_data['connections'] = connections
                    if network_stats:
                        self.current_data['traffic_rate'] = total_bytes / 1024
                        self.current_data['packet_rate'] = total_packets
                    self.current_data['system_stats'] = self.get_system_stats()
                
                time.sleep(self.interval)
            except Exception as e:
                self.logger.error(f"Baseline error: {e}")
                break

        if conn_samples and byte_samples and packet_samples:
            self.baseline_connections = statistics.mean(conn_samples)
            self.baseline_bytes = statistics.mean(byte_samples)
            self.baseline_packets = statistics.mean(packet_samples)
            self.baseline_established = True
            
            if len(byte_samples) > 1:
                self.baseline_bytes_std = statistics.stdev(byte_samples)
            else:
                self.baseline_bytes_std = self.baseline_bytes * 0.1
                
            if len(packet_samples) > 1:
                self.baseline_packets_std = statistics.stdev(packet_samples)
            else:
                self.baseline_packets_std = self.baseline_packets * 0.1
            
            with self.data_lock:
                self.current_data['baseline_info'] = {
                    'connections': self.baseline_connections,
                    'traffic': self.baseline_bytes / 1024,
                    'packets': self.baseline_packets,
                    'established': True
                }
            
            self.logger.info(
                f"Baseline established - "
                f"Connections: {self.baseline_connections:.2f}, "
                f"Traffic: {self.baseline_bytes / 1024:.2f} KB, "
                f"Packets: {self.baseline_packets:.0f}"
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
        
        self.logger.info("Enhanced monitoring started")

    def stop_monitoring(self) -> None:
        """Stop the monitoring thread."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
        
        with self.data_lock:
            self.current_data['status'] = {'text': 'Monitoring stopped', 'color': 'secondary'}
        
        self.logger.info("Monitoring stopped")

    def _monitor_loop(self) -> None:
        """Enhanced monitoring loop with improved detection"""
        if not self.baseline_established:
            self.establish_baseline()

        prev_network_stats = self.get_enhanced_network_stats()
        if not prev_network_stats:
            self.logger.error("Failed to get initial network stats")
            return

        while not self._stop_event.is_set():
            try:
                timestamp = datetime.now()
                connections, by_proc, by_endpoint = self.get_connections()
                curr_network_stats = self.get_enhanced_network_stats()
                
                if not curr_network_stats:
                    time.sleep(self.interval)
                    continue
                
                delta_sent = curr_network_stats['bytes_sent'] - prev_network_stats['bytes_sent']
                delta_recv = curr_network_stats['bytes_recv'] - prev_network_stats['bytes_recv']
                delta_total_bytes = delta_sent + delta_recv
                
                delta_packets_sent = curr_network_stats['packets_sent'] - prev_network_stats['packets_sent']
                delta_packets_recv = curr_network_stats['packets_recv'] - prev_network_stats['packets_recv']
                delta_total_packets = delta_packets_sent + delta_packets_recv
                
                self.connection_history.append(connections)
                self.bytes_history.append(delta_total_bytes)
                self.packet_history.append(delta_total_packets)
                
                self._perform_enhanced_analysis(
                    connections, delta_total_bytes, delta_total_packets,
                    by_endpoint, timestamp
                )
                
                top_suspicious = self._get_top_suspicious_endpoints()
                
                top_endpoints = sorted(
                    by_endpoint.items(),
                    key=lambda x: x[1]['count'],
                    reverse=True
                )[:10]

                with self.data_lock:
                    self.current_data.update({
                        'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        'status': self._get_status(connections, delta_total_bytes),
                        'connections': connections,
                        'traffic_rate': delta_total_bytes / 1024,
                        'packet_rate': delta_total_packets,
                        'connection_states': getattr(self, 'connection_states', {}),
                        'traffic_breakdown': {
                            'sent': delta_sent,
                            'received': delta_recv,
                            'packets_sent': delta_packets_sent,
                            'packets_received': delta_packets_recv
                        },
                        'top_processes': sorted(by_proc.items(), key=lambda x: x[1], reverse=True)[:5],
                        'top_endpoints': top_endpoints,
                        'suspicious_endpoints': top_suspicious,
                        'attack_summary': self._get_attack_summary(),
                        'system_stats': self.get_system_stats(),
                        'history': self._update_history(connections, delta_total_bytes, delta_total_packets)
                    })
                
                prev_network_stats = curr_network_stats
                time.sleep(self.interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                time.sleep(5)

    def _perform_enhanced_analysis(self, connections: int, delta_bytes: int, 
                                 delta_packets: int, endpoints: Dict, timestamp: datetime):
        """Perform enhanced analysis and alert detection"""
        alerts = []
        
        # 1. Connection threshold analysis
        if connections > self.threshold:
            alert = {
                'type': 'CRITICAL',
                'category': 'CONNECTION_FLOOD',
                'message': f"Connection count ({connections}) exceeded threshold ({self.threshold})",
                'details': {
                    'current': connections,
                    'threshold': self.threshold,
                    'baseline': self.baseline_connections
                },
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'severity': 'HIGH'
            }
            alerts.append(alert)
            self.attack_patterns['connection_flood']['detected'] = True
            self.attack_patterns['connection_flood']['count'] += 1
            self.attack_patterns['connection_flood']['last_seen'] = timestamp
            self.logger.critical(f"CONNECTION FLOOD DETECTED: {connections} connections")

        # 2. Traffic spike detection - FIXED: More sensitive detection
        if self.baseline_established and len(self.bytes_history) > 3:
            recent_bytes = list(self.bytes_history)[-5:]
            avg_recent = statistics.mean(recent_bytes)
            
            # FIXED: Lowered sensitivity threshold
            spike_threshold = self.baseline_bytes + (self.spike_detection_sensitivity * self.baseline_bytes_std)
            
            # NEW: Absolute traffic flood detection (5x baseline)
            traffic_ratio = delta_bytes / max(self.baseline_bytes, 1)
            if traffic_ratio > self.traffic_flood_threshold:
                alert = {
                    'type': 'CRITICAL',
                    'category': 'TRAFFIC_FLOOD',
                    'message': f"Massive traffic flood detected: {delta_bytes / 1024:.2f} KB/s ({traffic_ratio:.1f}x baseline)",
                    'details': {
                        'current_rate': f"{delta_bytes / 1024:.2f} KB/s",
                        'baseline_rate': f"{self.baseline_bytes / 1024:.2f} KB/s",
                        'traffic_ratio': f"{traffic_ratio:.1f}x",
                        'threshold': f"{self.traffic_flood_threshold}x baseline"
                    },
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': 'HIGH'
                }
                alerts.append(alert)
                self.attack_patterns['traffic_flood']['detected'] = True
                self.attack_patterns['traffic_flood']['count'] += 1
                self.attack_patterns['traffic_flood']['last_seen'] = timestamp
                self.logger.critical(f"TRAFFIC FLOOD: {delta_bytes/1024:.2f} KB/s ({traffic_ratio:.1f}x baseline)")
            
            # Existing statistical spike detection
            elif delta_bytes > spike_threshold and delta_bytes > self.minimum_spike_threshold * 1024:
                severity = 'HIGH' if delta_bytes > spike_threshold * 2 else 'MEDIUM'
                alert = {
                    'type': 'WARNING' if severity == 'MEDIUM' else 'CRITICAL',
                    'category': 'TRAFFIC_SPIKE',
                    'message': f"Traffic spike detected: {delta_bytes / 1024:.2f} KB/s",
                    'details': {
                        'current_rate': f"{delta_bytes / 1024:.2f} KB/s",
                        'baseline_rate': f"{self.baseline_bytes / 1024:.2f} KB/s",
                        'spike_factor': f"{delta_bytes / max(self.baseline_bytes, 1):.2f}x",
                        'threshold': f"{spike_threshold / 1024:.2f} KB/s"
                    },
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': severity
                }
                alerts.append(alert)
                self.logger.warning(f"TRAFFIC SPIKE: {delta_bytes/1024:.2f} KB/s")

        # 3. Packet flood detection
        if self.baseline_established and delta_packets > 0:
            packet_spike_threshold = self.baseline_packets + (self.spike_detection_sensitivity * self.baseline_packets_std)
            
            if delta_packets > packet_spike_threshold and delta_packets > 50:  # Lowered from 100 to 50
                alert = {
                    'type': 'CRITICAL',
                    'category': 'PACKET_FLOOD',
                    'message': f"Packet flood detected: {delta_packets} packets/s",
                    'details': {
                        'current_rate': f"{delta_packets} packets/s",
                        'baseline_rate': f"{self.baseline_packets:.0f} packets/s",
                        'spike_factor': f"{delta_packets / max(self.baseline_packets, 1):.2f}x"
                    },
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': 'HIGH'
                }
                alerts.append(alert)
                self.logger.critical(f"PACKET FLOOD: {delta_packets} packets/s")

        # 4. Endpoint behavior analysis
        for endpoint, data in endpoints.items():
            if data['count'] > 10:  # Lowered from 20 to 10
                alert = {
                    'type': 'WARNING',
                    'category': 'SUSPICIOUS_ENDPOINT',
                    'message': f"High connection count from {endpoint.split(':')[0]}: {data['count']} connections",
                    'details': {
                        'endpoint': endpoint,
                        'connections': data['count'],
                        'ports': len(data['ports']),
                        'processes': len(data['processes'])
                    },
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': 'MEDIUM'
                }
                alerts.append(alert)

        # 5. Rate of change analysis
        if len(self.connection_history) >= 3:
            recent_connections = list(self.connection_history)[-3:]
            connection_growth_rate = (recent_connections[-1] - recent_connections[0]) / 2
            
            if connection_growth_rate > 30:  # Lowered from 50 to 30
                alert = {
                    'type': 'WARNING',
                    'category': 'RAPID_GROWTH',
                    'message': f"Rapid connection growth: +{connection_growth_rate:.0f} connections in 2 seconds",
                    'details': {
                        'growth_rate': f"{connection_growth_rate:.0f}/sec",
                        'from': recent_connections[0],
                        'to': recent_connections[-1]
                    },
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': 'MEDIUM'
                }
                alerts.append(alert)

        # Store alerts
        with self.data_lock:
            self.current_data['alerts'] = (self.current_data['alerts'] + alerts)[-50:]
            
        for alert in alerts:
            if alert['type'] == 'CRITICAL':
                self.logger.critical(f"{alert['category']}: {alert['message']}")
            else:
                self.logger.warning(f"{alert['category']}: {alert['message']}")

    def _get_top_suspicious_endpoints(self) -> List[Dict]:
        """Get top suspicious endpoints with details"""
        suspicious_list = []
        
        for endpoint, data in self.suspicious_endpoints.items():
            if data['suspicious_score'] > 5:  # Lowered from 10 to 5
                suspicious_list.append({
                    'endpoint': endpoint,
                    'ip': endpoint.split(':')[0],
                    'port': endpoint.split(':')[1] if ':' in endpoint else 'N/A',
                    'score': data['suspicious_score'],
                    'connections': data['connection_count'],
                    'ports_targeted': len(data['ports_targeted']),
                    'processes': len(data['processes_involved']),
                    'flags': data['flags'],
                    'first_seen': data['first_seen'].strftime("%H:%M:%S"),
                    'last_activity': data['last_activity'].strftime("%H:%M:%S")
                })
        
        return sorted(suspicious_list, key=lambda x: x['score'], reverse=True)[:10]

    def _get_attack_summary(self) -> Dict:
        """Get summary of detected attack patterns"""
        return {
            pattern: {
                'detected': data['detected'],
                'count': data['count'],
                'last_seen': data['last_seen'].strftime("%Y-%m-%d %H:%M:%S") if data['last_seen'] else 'Never'
            }
            for pattern, data in self.attack_patterns.items()
        }

    def _update_history(self, conns: int, bytes: int, packets: int) -> Dict:
        """Maintain historical data for charts including packet history"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        history = self.current_data['history']
        max_points = 60
        
        for key in ['connections', 'traffic', 'packets', 'labels']:
            if len(history[key]) >= max_points:
                history[key].pop(0)
        
        history['connections'].append(conns)
        history['traffic'].append(bytes / 1024)
        history['packets'].append(packets)
        history['labels'].append(timestamp)
        
        return history

    def _get_status(self, conns: int, traffic_bytes: int = 0) -> Dict:
        """Enhanced status determination with traffic consideration"""
        conn_usage = conns / self.threshold
        
        # FIXED: Improved traffic-based detection
        traffic_anomaly = False
        traffic_ratio = 0
        if self.baseline_established and self.baseline_bytes > 0:
            traffic_ratio = traffic_bytes / max(self.baseline_bytes, 1)
            traffic_anomaly = traffic_ratio > 2.0
        
        # NEW: Traffic flood takes highest priority
        if traffic_ratio > self.traffic_flood_threshold:
            return {'text': 'CRITICAL: Massive traffic flood detected!', 'color': 'danger'}
        elif conn_usage >= 1.0:
            return {'text': 'CRITICAL: Connection flood detected!', 'color': 'danger'}
        elif conn_usage >= self.alert_threshold or traffic_anomaly:
            return {'text': 'WARNING: Suspicious traffic patterns', 'color': 'warning'}
        elif any(pattern['detected'] for pattern in self.attack_patterns.values() if pattern['count'] > 0):
            return {'text': 'ALERT: Attack patterns identified', 'color': 'warning'}
        
        return {'text': 'OK: Normal traffic patterns', 'color': 'success'}

    def get_system_stats(self) -> Dict:
        """Get current system resource usage."""
        try:
            return {
                'cpu': psutil.cpu_percent(),
                'memory': psutil.virtual_memory().percent,
                'network': {
                    'sent': psutil.net_io_counters().bytes_sent,
                    'recv': psutil.net_io_counters().bytes_recv
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting system stats: {e}")
            return {'cpu': 0, 'memory': 0, 'network': {'sent': 0, 'recv': 0}}

    def get_status_data(self) -> Dict:
        """Get current monitoring data for API."""
        with self.data_lock:
            return self.current_data.copy()

    def generate_attack_report(self) -> str:
        """Generate a detailed attack report"""
        report = []
        report.append("=== DDoS Attack Analysis Report ===")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        status = self.current_data.get('status', {})
        report.append(f"Current Status: {status.get('text', 'Unknown')}")
        report.append("")
        
        report.append("System Information:")
        host_info = self.current_data.get('host_info', {})
        report.append(f"  Hostname: {host_info.get('hostname', 'Unknown')}")
        report.append(f"  IP Address: {host_info.get('ip', 'Unknown')}")
        report.append(f"  OS: {host_info.get('os', 'Unknown')}")
        report.append("")
        
        report.append("Current Metrics:")
        report.append(f"  Active Connections: {self.current_data.get('connections', 0)}")
        report.append(f"  Traffic Rate: {self.current_data.get('traffic_rate', 0):.2f} KB/s")
        report.append(f"  Packet Rate: {self.current_data.get('packet_rate', 0)} packets/s")
        report.append("")
        
        if self.baseline_established:
            report.append("Baseline Comparison:")
            report.append(f"  Baseline Connections: {self.baseline_connections:.2f}")
            report.append(f"  Baseline Traffic: {self.baseline_bytes / 1024:.2f} KB/s")
            report.append(f"  Baseline Packets: {self.baseline_packets:.0f} packets/s")
            report.append("")
        
        alerts = self.current_data.get('alerts', [])
        if alerts:
            report.append("Recent Alerts:")
            for alert in alerts[-10:]:  # Last 10 alerts
                report.append(f"  [{alert.get('type', 'UNKNOWN')}] {alert.get('message', 'No message')}")
        else:
            report.append("No recent alerts")
        
        return "\n".join(report)