from flask import Blueprint, render_template, jsonify, request
from app.detector import DDoSDetector

main_bp = Blueprint('main', __name__)
detector = DDoSDetector()

@main_bp.route('/')
def dashboard():
    data = detector.get_status_data()
    return render_template('dashboard.html', data=data)

@main_bp.route('/data')
def get_data():
    return jsonify(detector.get_status_data())

@main_bp.route('/start')
def start_monitoring():
    detector.start_monitoring()
    return jsonify({'status': 'Monitoring started'})

@main_bp.route('/stop')
def stop_monitoring():
    detector.stop_monitoring()
    return jsonify({'status': 'Monitoring stopped'})

@main_bp.route('/settings', methods=['POST'])
def update_settings():
    data = request.get_json()
    try:
        detector.update_settings(
            threshold=int(data['threshold']),
            alert_threshold=float(data['alertThreshold']) / 100,
            interval=float(data['interval']) / 1000
        )
        return jsonify({'status': 'Settings updated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400