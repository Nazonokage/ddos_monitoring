from flask import Blueprint, render_template, jsonify
from app.detector import DDoSDetector

main_bp = Blueprint('main', __name__)
detector = DDoSDetector()

@main_bp.route('/')
def dashboard():
    # Get current data and pass it to the template
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