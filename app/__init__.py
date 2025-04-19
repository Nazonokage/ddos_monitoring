from flask import Flask
from .detector import DDoSDetector

def create_app():
    app = Flask(__name__)
    app.detector = DDoSDetector()  # Initialize detector
    
    from .routes import main_bp
    app.register_blueprint(main_bp)
    
    return app