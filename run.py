import webbrowser
from threading import Timer
from app import create_app

app = create_app()

def open_browser():
    webbrowser.open_new("http://127.0.0.1:8060")

if __name__ == '__main__':
    Timer(1, open_browser).start()
    app.run(host='0.0.0.0', port=8060, debug=False)
