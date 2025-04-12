# DDoS Detection System 🛡️

A real-time DDoS/DoS detection system with web interface, providing network monitoring, anomaly detection, and alerting capabilities.

![Dashboard Screenshot](screenshot.png) *(Example screenshot placeholder)*

## Features ✨

- **Real-time Monitoring**:
  - Active network connection tracking
  - Traffic rate analysis (incoming/outgoing)
  - Process-level connection breakdown

- **Advanced Detection**:
  - Threshold-based alerts
  - Connection spike detection
  - Traffic volume anomalies
  - Baseline establishment for normal activity

- **Web Dashboard**:
  - Interactive charts for historical data
  - Color-coded status indicators
  - Alert notifications with timestamps
  - System resource monitoring (CPU, memory)

- **Technical Highlights**:
  - Multi-threaded monitoring backend
  - Responsive Bootstrap UI
  - Chart.js visualizations
  - RESTful API for frontend-backend communication

## Installation 🛠️

### Prerequisites
- Python 3.8+
- pip package manager
- Virtual environment (recommended)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ddos-detector-web.git
   cd ddos-detector-web
   ```

2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate    # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables (optional):
   Create `.env` file:
   ```ini
   FLASK_DEBUG=1
   FLASK_ENV=development
   ```

## Project Structure 📂

```
ddos-web/
├── app/
│   ├── __init__.py         # Flask application factory
│   ├── detector.py         # Core detection logic
│   ├── routes.py           # Flask routes and views
│   ├── templates/
│   │   └── dashboard.html  # Main dashboard template
│   └── static/
│       ├── css/
│       │   └── style.css   # Custom styles
│       └── js/
│           └── app.js      # Frontend logic
├── run.py                  # Application entry point
└── requirements.txt        # Dependencies
```

## Usage 🚀

### Running the Application
```bash
python run.py
```

The web interface will be available at:  
[http://localhost:8060](http://localhost:8060)

### Using the Dashboard

1. **Start Monitoring**:
   - Click "Start" button to begin baseline establishment
   - System will monitor for 60 seconds to determine normal activity

2. **View Real-time Data**:
   - Connection count vs. threshold
   - Network traffic rates
   - Top processes making connections
   - System resource usage

3. **Alerts**:
   - Critical alerts appear when thresholds are exceeded
   - Warning alerts for suspicious activity
   - Alert history maintained in the dashboard

4. **Stop Monitoring**:
   - Click "Stop" to pause the monitoring

## Configuration ⚙️

### Detector Settings
Modify `app/detector.py` to adjust detection parameters:

```python
def __init__(self, 
             threshold=1000,       # Max connections before alert
             window=10,            # Analysis window in seconds
             alert_threshold=0.7,  # Warning level (70% of threshold)
             interval=1.0):        # Sampling interval
```

### Flask Settings
Edit `run.py` for server configuration:

```python
app.run(
    host='0.0.0.0',   # Listen on all network interfaces
    port=8060,        # Default port
    debug=True,       # Debug mode
    threaded=True     # Handle concurrent requests
)
```

## API Endpoints 🌐

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard view |
| `/data` | GET | JSON monitoring data |
| `/start` | GET | Start monitoring |
| `/stop` | GET | Stop monitoring |

## Dependencies 📦

- Python 3.8+
- Flask (Web framework)
- psutil (System monitoring)
- Chart.js (Data visualization)
- Bootstrap (UI components)
- Font Awesome (Icons)

## Troubleshooting 🔍

**Issue**: No data in charts  
**Solution**: Ensure monitoring is started and wait for baseline establishment (60 seconds)

**Issue**: "ImportError: cannot import name"  
**Solution**: Verify your project structure and PYTHONPATH

**Issue**: Permission errors  
**Solution**: Run with admin privileges if monitoring system processes

## Contributing 🤝

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments 🎓

- Inspired by network security monitoring tools
- Built with Flask and Python
- Chart.js for beautiful visualizations
- Bootstrap for responsive design
```
