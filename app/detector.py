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
    def __init__(self, threshold=500, window=10, alert_threshold=0.7, interval=1.0, whitelist_ips=None):
        """
        Enhanced DDoSDetector with improved attacker detection and threat scoring.
        
        Args:
            threshold: Max allowed connections before triggering critical alert
            window: Sliding time window in seconds for averages
            alert_threshold: Warning level (% of threshold) for moderate alerts
            interval: Sampling interval in seconds
            whitelist_ips: List of IPs to exclude from detection (trusted services)
        """
        self.threshold = threshold
        self.window = window
        self.alert_threshold = alert_threshold
        self.interval = interval
        self.whitelist_ips = set(whitelist_ips or [])

        # Configure logging FIRST
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('ddos_monitor.log', mode='a')
            ]
        )
        self.logger = logging.getLogger('EnhancedDDoSDetector')

        # Enhanced data structures for better detection
        self.connection_history: Deque[int] = collections.deque(maxlen=window * 2)
        self.bytes_history: Deque[int] = collections.deque(maxlen=window * 2)
        self.packet_history: Deque[int] = collections.deque(maxlen=window * 2)
        self.alert_history: List[Dict] = []
        self.connection_details: Dict[str, Dict] = {}
        self.host_info = self._get_host_info()
        
        # Get local IPs to exclude from attacker detection - ONLY ACTUAL LOCAL HOST IPS
        self.local_ips = self._get_local_ips()
        
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
            'traffic_flood': {'detected': False, 'count': 0, 'last_seen': None},
            'port_scanning': {'detected': False, 'count': 0, 'last_seen': None}
        }
        
        # Enhanced sensitivity settings
        self.spike_detection_sensitivity = 2.0
        self.minimum_spike_threshold = 50
        self.traffic_flood_threshold = 5.0
        
        # Enhanced attacker detection thresholds
        self.min_threat_score = 30  # Minimum score to flag as attacker
        self.rapid_connection_threshold = 10  # connections per minute
        self.port_scan_threshold = 5  # different ports
        self.syn_flood_ratio = 0.5  # 50% half-open connections
        
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
            },
            'attacker_info': [],
            'main_attacker': None
        }

        self.logger.info("EnhancedDDoSDetector initialized with improved threat detection")

    def _get_local_ips(self) -> set:
        """Get only THIS HOST'S IP addresses to exclude from attacker detection"""
        local_ips = set()
        try:
            # Get hostname
            hostname = socket.gethostname()
            
            # Get all IP addresses associated with hostname
            local_ips.add(socket.gethostbyname(hostname))
            
            # Get all interface IPs of THIS machine only
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        local_ips.add(addr.address)
                    elif addr.family == socket.AF_INET6:  # IPv6
                        local_ips.add(addr.address.split('%')[0])  # Remove scope ID
            
            # Add ONLY actual localhost IPs, NOT entire private ranges
            local_ips.update(['127.0.0.1', 'localhost', '::1', '0.0.0.0'])
            
            self.logger.info(f"Local HOST IPs excluded from detection: {local_ips}")
        except Exception as e:
            self.logger.error(f"Error getting local IPs: {e}")
        
        return local_ips

    def _is_local_ip(self, ip: str) -> bool:
        """Check if an IP is THIS HOST'S IP (should be excluded from attacker detection)"""
        if not ip or ip == "Unknown":
            return True
            
        # Check if IP is in THIS HOST'S IPs set
        if ip in self.local_ips:
            return True
            
        # Check if IP is in whitelist
        if ip in self.whitelist_ips:
            return True
            
        # DO NOT exclude private IP ranges - other devices on local network can be attackers!
        # Only exclude actual localhost
        if ip.startswith('127.') or ip == 'localhost' or ip == '::1':
            return True
            
        return False

    def _get_host_info(self) -> Dict:
        """Get system host information."""
        try:
            return {
                'hostname': socket.gethostname(),
                'os': f"{platform.system()} {platform.release()}",
                'ip': socket.gethostbyname(socket.gethostname()),
                'cpu_count': psutil.cpu_count(),
                'memory': round(psutil.virtual_memory().total / (1024**3), 2)
            }
        except Exception as e:
            self.logger.error(f"Error getting host info: {e}")
            return {'hostname': 'Unknown', 'os': 'Unknown', 'ip': 'Unknown', 'cpu_count': 0, 'memory': 0}

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

    def _extract_ip_from_endpoint(self, endpoint: str) -> str:
        """Safely extract IP from endpoint string"""
        if not endpoint or endpoint == "Unknown":
            return "Unknown"
        
        try:
            # Handle IPv6 addresses with brackets
            if endpoint.startswith('[') and ']' in endpoint:
                return endpoint.split('[')[1].split(']')[0]
            
            # Handle standard IP:port format
            if ':' in endpoint:
                parts = endpoint.split(':')
                # Handle IPv6 addresses without brackets
                if len(parts) > 2:  # IPv6 address
                    return ':'.join(parts[:-1])
                else:  # IPv4 address
                    return parts[0]
            
            return endpoint
        except Exception as e:
            self.logger.error(f"Error extracting IP from endpoint {endpoint}: {e}")
            return "Unknown"

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

        try:
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
                                # Skip ONLY this host's IPs, not other local network devices
                                remote_ip = self._extract_ip_from_endpoint(remote_addr)
                                if not self._is_local_ip(remote_ip):
                                    endpoint = by_endpoint[remote_addr]
                                    endpoint['count'] += 1
                                    if conn.laddr:
                                        endpoint['ports'].add(conn.laddr.port)
                                    endpoint['processes'].add(proc_name)
                                    endpoint['states'][conn.status] += 1
                                    endpoint['last_seen'] = datetime.now()
                                    
                                    self._analyze_endpoint_behavior(remote_addr, conn, proc_name)
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception as e:
            self.logger.error(f"Error getting connections: {e}")
                    
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
        """Enhanced endpoint behavior analysis with threat scoring"""
        current_time = datetime.now()
        remote_ip = self._extract_ip_from_endpoint(endpoint)
        
        # Skip ONLY this host's IPs
        if self._is_local_ip(remote_ip):
            return
            
        if endpoint not in self.suspicious_endpoints:
            self.suspicious_endpoints[endpoint] = {
                'connection_count': 0,
                'ports_targeted': set(),
                'processes_involved': set(),
                'states': collections.defaultdict(int),
                'first_seen': current_time,
                'last_activity': current_time,
                'threat_score': 0,
                'threat_indicators': [],
                'attack_pattern': 'UNKNOWN'
            }
        
        endpoint_data = self.suspicious_endpoints[endpoint]
        endpoint_data['connection_count'] += 1
        if conn.laddr:
            endpoint_data['ports_targeted'].add(conn.laddr.port)
        endpoint_data['processes_involved'].add(proc_name)
        endpoint_data['states'][conn.status] += 1
        endpoint_data['last_activity'] = current_time
        
        # Calculate threat score using the same method as attacker identification
        threat_score, threat_indicators, attack_pattern = self._calculate_threat_score(
            endpoint_data, current_time
        )
        
        endpoint_data['threat_score'] = threat_score
        endpoint_data['threat_indicators'] = threat_indicators
        endpoint_data['attack_pattern'] = attack_pattern
        
        # Clean up old entries with low threat
        if (current_time - endpoint_data['last_activity']).total_seconds() > 300 and threat_score < 15:
            del self.suspicious_endpoints[endpoint]

    def _calculate_threat_score(self, endpoint_data: Dict, current_time: datetime) -> Tuple[int, List[str], str]:
        """Calculate threat score based on multiple factors"""
        threat_score = 0
        threat_indicators = []
        
        # Calculate connection velocity (connections per minute)
        time_range = (current_time - endpoint_data['first_seen']).total_seconds() / 60
        connection_velocity = endpoint_data['connection_count'] / max(time_range, 0.1)
        
        # Factor 1: Absolute connection count
        if endpoint_data['connection_count'] > 50:
            threat_score += 40
            threat_indicators.append(f"High connection count: {endpoint_data['connection_count']}")
        elif endpoint_data['connection_count'] > 20:
            threat_score += 20
            threat_indicators.append(f"Elevated connections: {endpoint_data['connection_count']}")
        
        # Factor 2: Connection velocity (rapid connections)
        if connection_velocity > self.rapid_connection_threshold:
            threat_score += 30
            threat_indicators.append(f"Rapid connection rate: {connection_velocity:.1f}/min")
        
        # Factor 3: Port scanning behavior
        if len(endpoint_data['ports_targeted']) > self.port_scan_threshold:
            threat_score += 25
            threat_indicators.append(f"Port scanning: {len(endpoint_data['ports_targeted'])} ports")
        
        # Factor 4: Connection state anomalies
        total_connections = sum(endpoint_data['states'].values())
        if total_connections > 0:
            syn_ratio = (endpoint_data['states'].get('SYN_SENT', 0) + 
                        endpoint_data['states'].get('SYN_RECV', 0)) / total_connections
            if syn_ratio > self.syn_flood_ratio:
                threat_score += 35
                threat_indicators.append(f"SYN flood pattern: {syn_ratio:.1%}")
            
            # Time wait connections (potential slowloris)
            time_wait_ratio = endpoint_data['states'].get('TIME_WAIT', 0) / total_connections
            if time_wait_ratio > 0.5 and total_connections > 20:
                threat_score += 20
                threat_indicators.append(f"Potential slowloris: {time_wait_ratio:.1%}")
        
        # Factor 5: Multiple process targeting (unusual)
        if len(endpoint_data['processes_involved']) > 3:
            threat_score += 15
            threat_indicators.append(f"Multiple processes: {len(endpoint_data['processes_involved'])}")
        
        # Determine attack pattern
        attack_pattern = self._detect_connection_pattern(endpoint_data)
        
        return threat_score, threat_indicators, attack_pattern

    def _detect_connection_pattern(self, endpoint_data: Dict) -> str:
        """Detect the specific attack pattern being used"""
        states = endpoint_data['states']
        total = sum(states.values())
        
        if total == 0:
            return "UNKNOWN"
        
        # SYN flood: Many half-open connections
        syn_ratio = (states.get('SYN_SENT', 0) + states.get('SYN_RECV', 0)) / total
        if syn_ratio > self.syn_flood_ratio:
            return "SYN_FLOOD"
        
        # Connection flood: Many established connections
        established_ratio = states.get('ESTABLISHED', 0) / total
        if established_ratio > 0.7 and total > 50:
            return "CONNECTION_FLOOD"
        
        # Slowloris: Many TIME_WAIT connections
        time_wait_ratio = states.get('TIME_WAIT', 0) / total
        if time_wait_ratio > 0.5 and total > 20:
            return "SLOWLORIS"
        
        # Port scanning: Many different ports
        if len(endpoint_data['ports_targeted']) > self.port_scan_threshold:
            return "PORT_SCANNING"
        
        return "UNKNOWN"

    def _format_remote_addr(self, conn) -> Optional[str]:
        """Format remote address for consistent tracking."""
        if not conn.raddr:
            return None
            
        try:
            if ':' in conn.raddr.ip and '.' not in conn.raddr.ip:
                try:
                    ip = socket.inet_pton(socket.AF_INET6, conn.raddr.ip)
                    return socket.inet_ntop(socket.AF_INET6, ip) + f":{conn.raddr.port}"
                except:
                    pass
            return f"{conn.raddr.ip}:{conn.raddr.port}"
        except Exception as e:
            self.logger.error(f"Error formatting remote addr: {e}")
            return None

    def _identify_attackers(self, endpoints: Dict) -> List[Dict]:
        """Enhanced attacker identification with multi-factor threat scoring"""
        attackers = []
        current_time = datetime.now()
        
        for endpoint, data in endpoints.items():
            remote_ip = self._extract_ip_from_endpoint(endpoint)
            
            # Skip ONLY this host's IPs, but include other local network devices
            if self._is_local_ip(remote_ip):
                continue
            
            # Convert string timestamps back to datetime for calculations
            first_seen = datetime.fromisoformat(data['first_seen'].replace('Z', '+00:00'))
            time_range = (current_time - first_seen).total_seconds() / 60
            connection_velocity = data['count'] / max(time_range, 0.1)
            
            # Calculate threat score
            threat_score = 0
            threat_indicators = []
            
            # Factor 1: Absolute connection count
            if data['count'] > 50:
                threat_score += 40
                threat_indicators.append(f"High connection count: {data['count']}")
            elif data['count'] > 20:
                threat_score += 20
                threat_indicators.append(f"Elevated connections: {data['count']}")
            
            # Factor 2: Connection velocity
            if connection_velocity > self.rapid_connection_threshold:
                threat_score += 30
                threat_indicators.append(f"Rapid connection rate: {connection_velocity:.1f}/min")
            
            # Factor 3: Port scanning
            if len(data['ports']) > self.port_scan_threshold:
                threat_score += 25
                threat_indicators.append(f"Port scanning: {len(data['ports'])} ports")
            
            # Factor 4: Connection state anomalies
            total_connections = sum(data['states'].values())
            if total_connections > 0:
                syn_ratio = (data['states'].get('SYN_SENT', 0) + data['states'].get('SYN_RECV', 0)) / total_connections
                if syn_ratio > self.syn_flood_ratio:
                    threat_score += 35
                    threat_indicators.append(f"SYN flood pattern: {syn_ratio:.1%}")
            
            # Factor 5: Multiple processes
            if len(data['processes']) > 3:
                threat_score += 15
                threat_indicators.append(f"Multiple processes: {len(data['processes'])}")
            
            # Only flag as attacker if threat score exceeds minimum threshold
            if threat_score >= self.min_threat_score:
                threat_level = 'CRITICAL' if threat_score >= 70 else 'HIGH' if threat_score >= 50 else 'MEDIUM'
                attack_pattern = self._detect_attack_pattern_from_data(data)
                
                attacker_info = {
                    'ip': remote_ip,
                    'endpoint': endpoint,
                    'connection_count': data['count'],
                    'connection_velocity': round(connection_velocity, 2),
                    'ports_targeted': len(data['ports']),
                    'processes': data['processes'],
                    'threat_score': threat_score,
                    'threat_level': threat_level,
                    'threat_indicators': threat_indicators,
                    'attack_pattern': attack_pattern,
                    'first_seen': data['first_seen'],
                    'last_seen': data['last_seen'],
                    'connection_states': data['states']
                }
                attackers.append(attacker_info)
        
        return sorted(attackers, key=lambda x: x['threat_score'], reverse=True)

    def _detect_attack_pattern_from_data(self, data: Dict) -> str:
        """Detect attack pattern from endpoint data"""
        states = data['states']
        total = sum(states.values())
        
        if total == 0:
            return "UNKNOWN"
        
        # SYN flood detection
        syn_ratio = (states.get('SYN_SENT', 0) + states.get('SYN_RECV', 0)) / total
        if syn_ratio > self.syn_flood_ratio:
            return "SYN_FLOOD"
        
        # Connection flood
        established_ratio = states.get('ESTABLISHED', 0) / total
        if established_ratio > 0.7 and total > 50:
            return "CONNECTION_FLOOD"
        
        # Port scanning
        if len(data['ports']) > self.port_scan_threshold:
            return "PORT_SCANNING"
        
        return "UNKNOWN"

    def _get_main_attacker(self, endpoints: Dict) -> Optional[Dict]:
        """Get the main attacker with the highest threat score"""
        attackers = self._identify_attackers(endpoints)
        return attackers[0] if attackers else None

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
                f"Traffic: {self.baseline_bytes / 1024:.2f} KB/s, "
                f"Packets: {self.baseline_packets:.0f} packets/s"
            )
        else:
            self.logger.error("Failed to establish baseline - insufficient data")

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
                
                # Identify potential attackers with enhanced detection
                identified_attackers = self._identify_attackers(by_endpoint)
                main_attacker = self._get_main_attacker(by_endpoint)
                
                self._perform_enhanced_analysis(
                    connections, delta_total_bytes, delta_total_packets,
                    by_endpoint, timestamp, identified_attackers, main_attacker
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
                        'history': self._update_history(connections, delta_total_bytes, delta_total_packets),
                        'attacker_info': identified_attackers,
                        'main_attacker': main_attacker
                    })
                
                prev_network_stats = curr_network_stats
                time.sleep(self.interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                time.sleep(5)

    def _perform_enhanced_analysis(self, connections: int, delta_bytes: int, 
                                 delta_packets: int, endpoints: Dict, 
                                 timestamp: datetime, attackers: List[Dict], 
                                 main_attacker: Optional[Dict]):
        """Perform enhanced analysis and alert detection with attacker information"""
        alerts = []
        
        # Use main attacker if available, otherwise use top from list
        top_attacker = main_attacker or (attackers[0] if attackers else None)
        
        # 1. Connection threshold analysis
        if connections > self.threshold:
            alert_details = {
                'current': connections,
                'threshold': self.threshold,
                'baseline': self.baseline_connections
            }
            
            # Add attacker information if available
            if top_attacker:
                alert_details['attacker_ip'] = top_attacker['ip']
                alert_details['attacker_connections'] = top_attacker['connection_count']
                alert_details['attacker_ports'] = top_attacker['ports_targeted']
                alert_details['attacker_threat_score'] = top_attacker['threat_score']
                alert_details['attack_pattern'] = top_attacker['attack_pattern']
                alert_details['main_attacker'] = True
            
            alert = {
                'type': 'CRITICAL',
                'category': 'CONNECTION_FLOOD',
                'message': f"Connection count ({connections}) exceeded threshold ({self.threshold})" + 
                          (f" - Main attacker: {top_attacker['ip']} (threat: {top_attacker['threat_score']})" 
                           if top_attacker else ""),
                'details': alert_details,
                'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'severity': 'HIGH'
            }
            alerts.append(alert)
            self.attack_patterns['connection_flood']['detected'] = True
            self.attack_patterns['connection_flood']['count'] += 1
            self.attack_patterns['connection_flood']['last_seen'] = timestamp
            
            if top_attacker:
                self.logger.critical(f"CONNECTION FLOOD DETECTED: {connections} connections | Main attacker: {top_attacker['ip']} (threat: {top_attacker['threat_score']})")
            else:
                self.logger.critical(f"CONNECTION FLOOD DETECTED: {connections} connections")

        # 2. Traffic spike detection
        if self.baseline_established and len(self.bytes_history) > 3:
            recent_bytes = list(self.bytes_history)[-5:]
            avg_recent = statistics.mean(recent_bytes)
            
            spike_threshold = self.baseline_bytes + (self.spike_detection_sensitivity * self.baseline_bytes_std)
            
            # Traffic flood detection
            traffic_ratio = delta_bytes / max(self.baseline_bytes, 1)
            if traffic_ratio > self.traffic_flood_threshold:
                alert_details = {
                    'current_rate': f"{delta_bytes / 1024:.2f} KB/s",
                    'baseline_rate': f"{self.baseline_bytes / 1024:.2f} KB/s",
                    'traffic_ratio': f"{traffic_ratio:.1f}x",
                    'threshold': f"{self.traffic_flood_threshold}x baseline"
                }
                
                if top_attacker:
                    alert_details['attacker_ip'] = top_attacker['ip']
                    alert_details['main_attacker'] = True
                
                alert = {
                    'type': 'CRITICAL',
                    'category': 'TRAFFIC_FLOOD',
                    'message': f"Massive traffic flood: {delta_bytes / 1024:.2f} KB/s ({traffic_ratio:.1f}x baseline)" +
                              (f" - Main attacker: {top_attacker['ip']}" if top_attacker else ""),
                    'details': alert_details,
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': 'HIGH'
                }
                alerts.append(alert)
                self.attack_patterns['traffic_flood']['detected'] = True
                self.attack_patterns['traffic_flood']['count'] += 1
                self.attack_patterns['traffic_flood']['last_seen'] = timestamp
                
                if top_attacker:
                    self.logger.critical(f"TRAFFIC FLOOD: {delta_bytes/1024:.2f} KB/s ({traffic_ratio:.1f}x baseline) | Main attacker: {top_attacker['ip']}")
                else:
                    self.logger.critical(f"TRAFFIC FLOOD: {delta_bytes/1024:.2f} KB/s ({traffic_ratio:.1f}x baseline)")
            
            # Statistical spike detection
            elif delta_bytes > spike_threshold and delta_bytes > self.minimum_spike_threshold * 1024:
                severity = 'HIGH' if delta_bytes > spike_threshold * 2 else 'MEDIUM'
                alert_details = {
                    'current_rate': f"{delta_bytes / 1024:.2f} KB/s",
                    'baseline_rate': f"{self.baseline_bytes / 1024:.2f} KB/s",
                    'spike_factor': f"{delta_bytes / max(self.baseline_bytes, 1):.2f}x",
                    'threshold': f"{spike_threshold / 1024:.2f} KB/s"
                }
                
                if top_attacker:
                    alert_details['attacker_ip'] = top_attacker['ip']
                    alert_details['main_attacker'] = True
                
                alert = {
                    'type': 'WARNING' if severity == 'MEDIUM' else 'CRITICAL',
                    'category': 'TRAFFIC_SPIKE',
                    'message': f"Traffic spike: {delta_bytes / 1024:.2f} KB/s" +
                              (f" - Main attacker: {top_attacker['ip']}" if top_attacker else ""),
                    'details': alert_details,
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': severity
                }
                alerts.append(alert)
                
                if top_attacker:
                    self.logger.warning(f"TRAFFIC SPIKE: {delta_bytes/1024:.2f} KB/s | Main attacker: {top_attacker['ip']}")
                else:
                    self.logger.warning(f"TRAFFIC SPIKE: {delta_bytes/1024:.2f} KB/s")

        # 3. Packet flood detection
        if self.baseline_established and delta_packets > 0:
            packet_spike_threshold = self.baseline_packets + (self.spike_detection_sensitivity * self.baseline_packets_std)
            
            if delta_packets > packet_spike_threshold and delta_packets > 50:
                alert_details = {
                    'current_rate': f"{delta_packets} packets/s",
                    'baseline_rate': f"{self.baseline_packets:.0f} packets/s",
                    'spike_factor': f"{delta_packets / max(self.baseline_packets, 1):.2f}x"
                }
                
                if top_attacker:
                    alert_details['attacker_ip'] = top_attacker['ip']
                    alert_details['main_attacker'] = True
                
                alert = {
                    'type': 'CRITICAL',
                    'category': 'PACKET_FLOOD',
                    'message': f"Packet flood: {delta_packets} packets/s" +
                              (f" - Main attacker: {top_attacker['ip']}" if top_attacker else ""),
                    'details': alert_details,
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': 'HIGH'
                }
                alerts.append(alert)
                
                if top_attacker:
                    self.logger.critical(f"PACKET FLOOD: {delta_packets} packets/s | Main attacker: {top_attacker['ip']}")
                else:
                    self.logger.critical(f"PACKET FLOOD: {delta_packets} packets/s")

        # 4. Enhanced attacker alerts based on threat scoring
        for attacker in attackers[:3]:  # Top 3 attackers
            if attacker['threat_score'] >= 50:  # Only alert for high threat scores
                alert = {
                    'type': 'CRITICAL' if attacker['threat_score'] >= 70 else 'WARNING',
                    'category': 'IDENTIFIED_ATTACKER',
                    'message': f"High threat attacker detected: {attacker['ip']} (score: {attacker['threat_score']})",
                    'details': {
                        'attacker_ip': attacker['ip'],
                        'threat_score': attacker['threat_score'],
                        'threat_level': attacker['threat_level'],
                        'attack_pattern': attacker['attack_pattern'],
                        'connection_count': attacker['connection_count'],
                        'ports_targeted': attacker['ports_targeted'],
                        'main_attacker': (top_attacker and top_attacker['ip'] == attacker['ip'])
                    },
                    'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'severity': attacker['threat_level']
                }
                alerts.append(alert)

        # Store alerts
        with self.data_lock:
            self.current_data['alerts'] = (self.current_data.get('alerts', []) + alerts)[-50:]
            
        for alert in alerts:
            if alert['type'] == 'CRITICAL':
                self.logger.critical(f"{alert['category']}: {alert['message']}")
            else:
                self.logger.warning(f"{alert['category']}: {alert['message']}")

    def _get_top_suspicious_endpoints(self) -> List[Dict]:
        """Get top suspicious endpoints with enhanced details"""
        suspicious_list = []
        
        for endpoint, data in self.suspicious_endpoints.items():
            remote_ip = self._extract_ip_from_endpoint(endpoint)
            
            # Skip ONLY this host's IPs
            if self._is_local_ip(remote_ip):
                continue
                
            if data['threat_score'] > 5:
                suspicious_list.append({
                    'endpoint': endpoint,
                    'ip': remote_ip,
                    'port': endpoint.split(':')[1] if ':' in endpoint else 'N/A',
                    'threat_score': data['threat_score'],
                    'attack_pattern': data['attack_pattern'],
                    'connections': data['connection_count'],
                    'ports_targeted': len(data['ports_targeted']),
                    'processes': len(data['processes_involved']),
                    'threat_indicators': data['threat_indicators'],
                    'first_seen': data['first_seen'].strftime("%H:%M:%S"),
                    'last_activity': data['last_activity'].strftime("%H:%M:%S")
                })
        
        return sorted(suspicious_list, key=lambda x: x['threat_score'], reverse=True)[:10]

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

    def _update_history(self, conns: int, bytes_val: int, packets: int) -> Dict:
        """Maintain historical data for charts including packet history"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        history = self.current_data.get('history', {'connections': [], 'traffic': [], 'packets': [], 'labels': []})
        max_points = 60
        
        for key in ['connections', 'traffic', 'packets', 'labels']:
            if len(history[key]) >= max_points:
                history[key].pop(0)
        
        history['connections'].append(conns)
        history['traffic'].append(bytes_val / 1024)
        history['packets'].append(packets)
        history['labels'].append(timestamp)
        
        return history

    def _get_status(self, conns: int, traffic_bytes: int = 0) -> Dict:
        """Enhanced status determination with traffic consideration"""
        conn_usage = conns / self.threshold
        
        traffic_anomaly = False
        traffic_ratio = 0
        if self.baseline_established and self.baseline_bytes > 0:
            traffic_ratio = traffic_bytes / max(self.baseline_bytes, 1)
            traffic_anomaly = traffic_ratio > 2.0
        
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
        """Generate a detailed attack report with enhanced threat information"""
        report = []
        report.append("=== Enhanced DDoS Attack Analysis Report ===")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        data = self.get_status_data()
        status = data.get('status', {})
        report.append(f"Current Status: {status.get('text', 'Unknown')}")
        report.append("")
        
        report.append("System Information:")
        host_info = data.get('host_info', {})
        report.append(f"  Hostname: {host_info.get('hostname', 'Unknown')}")
        report.append(f"  IP Address: {host_info.get('ip', 'Unknown')}")
        report.append(f"  OS: {host_info.get('os', 'Unknown')}")
        report.append("")
        
        report.append("Current Metrics:")
        report.append(f"  Active Connections: {data.get('connections', 0)}")
        report.append(f"  Traffic Rate: {data.get('traffic_rate', 0):.2f} KB/s")
        report.append(f"  Packet Rate: {data.get('packet_rate', 0)} packets/s")
        report.append("")
        
        # Main attacker information with enhanced details
        main_attacker = data.get('main_attacker')
        if main_attacker:
            report.append("MAIN ATTACKER IDENTIFIED:")
            report.append(f"  IP Address: {main_attacker['ip']}")
            report.append(f"  Threat Score: {main_attacker['threat_score']}/100")
            report.append(f"  Threat Level: {main_attacker['threat_level']}")
            report.append(f"  Attack Pattern: {main_attacker['attack_pattern']}")
            report.append(f"  Connection Count: {main_attacker['connection_count']}")
            report.append(f"  Connection Velocity: {main_attacker['connection_velocity']}/min")
            report.append(f"  Ports Targeted: {main_attacker['ports_targeted']}")
            report.append("  Threat Indicators:")
            for indicator in main_attacker.get('threat_indicators', []):
                report.append(f"    - {indicator}")
            report.append("")
        
        # All attacker information
        attackers = data.get('attacker_info', [])
        if attackers:
            report.append("All Identified Attackers:")
            for attacker in attackers[:5]:
                report.append(f"  IP: {attacker['ip']}")
                report.append(f"    Threat Score: {attacker['threat_score']}/100 ({attacker['threat_level']})")
                report.append(f"    Attack Pattern: {attacker['attack_pattern']}")
                report.append(f"    Connections: {attacker['connection_count']}")
                report.append(f"    Connection Velocity: {attacker['connection_velocity']}/min")
                report.append(f"    Ports Targeted: {attacker['ports_targeted']}")
                report.append("")
        else:
            report.append("No high-threat attackers identified")
            report.append("")
        
        if self.baseline_established:
            report.append("Baseline Comparison:")
            report.append(f"  Baseline Connections: {self.baseline_connections:.2f}")
            report.append(f"  Baseline Traffic: {self.baseline_bytes / 1024:.2f} KB/s")
            report.append(f"  Baseline Packets: {self.baseline_packets:.0f} packets/s")
            report.append("")
        
        alerts = data.get('alerts', [])
        if alerts:
            report.append("Recent Alerts:")
            for alert in alerts[-10:]:
                report.append(f"  [{alert.get('type', 'UNKNOWN')}] {alert.get('message', 'No message')}")
                details = alert.get('details', {})
                if details.get('attacker_ip'):
                    report.append(f"     Attacker IP: {details['attacker_ip']}")
                    if details.get('threat_score'):
                        report.append(f"     Threat Score: {details['threat_score']}")
                    if details.get('attack_pattern'):
                        report.append(f"     Attack Pattern: {details['attack_pattern']}")
        else:
            report.append("No recent alerts")
        
        return "\n".join(report)