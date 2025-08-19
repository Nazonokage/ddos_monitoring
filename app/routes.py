from flask import Blueprint, render_template, jsonify, send_file, request, Response
import os
import json
from datetime import datetime
from app.detector import EnhancedDDoSDetector  # Updated import

main_bp = Blueprint('main', __name__)
detector = EnhancedDDoSDetector(
    threshold=500,  # Lower threshold for testing with hping3
    window=15,      # Longer window for better analysis
    alert_threshold=0.6,  # More sensitive
    interval=0.5    # Faster sampling for better spike detection
)

@main_bp.route('/')
def dashboard():
    """Main dashboard route"""
    data = detector.get_status_data()
    return render_template('dashboard.html', data=data)

@main_bp.route('/data')
def get_data():
    """API endpoint for real-time monitoring data"""
    return jsonify(detector.get_status_data())

@main_bp.route('/start')
def start_monitoring():
    """Start the monitoring system"""
    try:
        detector.start_monitoring()
        return jsonify({
            'status': 'Monitoring started',
            'message': 'Enhanced DDoS monitoring is now active',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'Error',
            'message': f'Failed to start monitoring: {str(e)}'
        }), 500

@main_bp.route('/stop')
def stop_monitoring():
    """Stop the monitoring system"""
    try:
        detector.stop_monitoring()
        return jsonify({
            'status': 'Monitoring stopped',
            'message': 'Monitoring has been stopped',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'Error',
            'message': f'Failed to stop monitoring: {str(e)}'
        }), 500

@main_bp.route('/settings', methods=['POST'])
def update_settings():
    """Update monitoring settings"""
    try:
        settings = request.get_json()
        
        # Validate settings
        if 'threshold' in settings:
            detector.threshold = max(1, int(settings['threshold']))
        if 'alert_threshold' in settings:
            detector.alert_threshold = max(0.1, min(0.99, float(settings['alert_threshold'])))
        if 'interval' in settings:
            detector.interval = max(0.1, float(settings['interval']))
        
        # Update current data settings
        with detector.data_lock:
            detector.current_data['settings'].update({
                'threshold': detector.threshold,
                'alert_threshold': detector.alert_threshold,
                'interval': detector.interval
            })
        
        return jsonify({
            'success': True,
            'message': 'Settings updated successfully',
            'settings': {
                'threshold': detector.threshold,
                'alert_threshold': detector.alert_threshold,
                'interval': detector.interval
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error updating settings: {str(e)}'
        }), 400

@main_bp.route('/report')
def get_attack_report():
    """Generate and return detailed attack report"""
    try:
        report = detector.generate_attack_report()
        return jsonify({
            'report': report,
            'timestamp': datetime.now().isoformat(),
            'format': 'text'
        })
    except Exception as e:
        return jsonify({
            'error': f'Failed to generate report: {str(e)}'
        }), 500

@main_bp.route('/report/download')
def download_report():
    """Download attack report as text file"""
    try:
        report = detector.generate_attack_report()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'ddos_attack_report_{timestamp}.txt'
        
        # Create temporary file
        temp_path = f'/tmp/{filename}'
        with open(temp_path, 'w') as f:
            f.write(report)
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='text/plain'
        )
    except Exception as e:
        return jsonify({
            'error': f'Failed to download report: {str(e)}'
        }), 500

@main_bp.route('/export')
def export_data():
    """Export all monitoring data to JSON"""
    try:
        filename = detector.export_data()
        if filename:
            return send_file(
                filename,
                as_attachment=True,
                download_name=filename,
                mimetype='application/json'
            )
        else:
            return jsonify({'error': 'Failed to export data'}), 500
    except Exception as e:
        return jsonify({
            'error': f'Export failed: {str(e)}'
        }), 500

@main_bp.route('/alerts')
def get_alerts():
    """Get current alerts with filtering options"""
    try:
        alert_type = request.args.get('type')  # CRITICAL, WARNING, etc.
        category = request.args.get('category')  # TRAFFIC_SPIKE, CONNECTION_FLOOD, etc.
        limit = request.args.get('limit', 50, type=int)
        
        alerts = detector.get_status_data().get('alerts', [])
        
        # Filter alerts
        if alert_type:
            alerts = [a for a in alerts if a.get('type') == alert_type.upper()]
        if category:
            alerts = [a for a in alerts if a.get('category') == category.upper()]
        
        # Limit results
        alerts = alerts[-limit:] if limit else alerts
        
        return jsonify({
            'alerts': alerts,
            'total_count': len(alerts),
            'filters_applied': {
                'type': alert_type,
                'category': category,
                'limit': limit
            }
        })
    except Exception as e:
        return jsonify({
            'error': f'Failed to get alerts: {str(e)}'
        }), 500

@main_bp.route('/suspicious')
def get_suspicious_endpoints():
    """Get detailed information about suspicious endpoints"""
    try:
        data = detector.get_status_data()
        suspicious = data.get('suspicious_endpoints', [])
        
        return jsonify({
            'suspicious_endpoints': suspicious,
            'count': len(suspicious),
            'high_risk': [s for s in suspicious if s['score'] > 50],
            'medium_risk': [s for s in suspicious if 20 <= s['score'] <= 50],
            'low_risk': [s for s in suspicious if s['score'] < 20]
        })
    except Exception as e:
        return jsonify({
            'error': f'Failed to get suspicious endpoints: {str(e)}'
        }), 500

@main_bp.route('/baseline/reset', methods=['POST'])
def reset_baseline():
    """Reset and re-establish baseline"""
    try:
        # Reset baseline flags
        detector.baseline_established = False
        detector.baseline_connections = 0
        detector.baseline_bytes = 0
        detector.baseline_packets = 0
        
        # Clear attack patterns
        for pattern in detector.attack_patterns:
            detector.attack_patterns[pattern] = {
                'detected': False, 
                'count': 0, 
                'last_seen': None
            }
        
        return jsonify({
            'success': True,
            'message': 'Baseline will be re-established on next monitoring cycle',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error resetting baseline: {str(e)}'
        }), 500

@main_bp.route('/test/simulate', methods=['POST'])
def simulate_attack():
    """Simulate attack patterns for testing (development only)"""
    try:
        attack_type = request.get_json().get('type', 'traffic_spike')
        
        if attack_type == 'traffic_spike':
            # Simulate a traffic spike by adding fake data
            fake_bytes = 50000000  # 50MB spike
            detector.bytes_history.append(fake_bytes)
            
            # Add alert manually for testing
            alert = {
                'type': 'CRITICAL',
                'category': 'SIMULATED_TRAFFIC_SPIKE',
                'message': f'Simulated traffic spike: {fake_bytes / 1024:.2f} KB',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'severity': 'HIGH',
                'details': {
                    'simulated': True,
                    'spike_size': f'{fake_bytes / 1024:.2f} KB'
                }
            }
            
            with detector.data_lock:
                detector.current_data['alerts'].append(alert)
        
        return jsonify({
            'success': True,
            'message': f'Simulated {attack_type} attack',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Simulation failed: {str(e)}'
        }), 500

@main_bp.route('/status')
def get_system_status():
    """Get comprehensive system status"""
    try:
        data = detector.get_status_data()
        
        return jsonify({
            'monitoring_active': detector._monitor_thread and detector._monitor_thread.is_alive(),
            'baseline_established': detector.baseline_established,
            'current_connections': data.get('connections', 0),
            'current_traffic': data.get('traffic_rate', 0),
            'alert_count': len(data.get('alerts', [])),
            'suspicious_endpoint_count': len(data.get('suspicious_endpoints', [])),
            'attack_patterns_detected': sum(1 for p in detector.attack_patterns.values() if p['detected']),
            'uptime': datetime.now().isoformat(),
            'settings': data.get('settings', {})
        })
    except Exception as e:
        return jsonify({
            'error': f'Failed to get status: {str(e)}'
        }), 500