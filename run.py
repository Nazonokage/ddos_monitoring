import os
import webbrowser
from threading import Timer
from app import create_app

portnum = 8070  # Move port number to a variable

app = create_app()

def open_browser():
    if not os.environ.get('WERKZEUG_RUN_MAIN') == 'true':  # Fix for Flask reloader
        webbrowser.open_new(f"http://127.0.0.1:{portnum}")  # Use f-string to inject port

if __name__ == '__main__':
    Timer(1, open_browser).start()
    app.run(host='0.0.0.0', port=portnum, debug=True)
