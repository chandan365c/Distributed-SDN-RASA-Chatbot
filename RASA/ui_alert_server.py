# ui_alert_server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import time
import threading

app = Flask(__name__)
CORS(app)

# Store list of alerts with timestamps
alerts = []

# Lock to safely access the queue from multiple threads
queue_lock = threading.Lock()

@app.route('/push_alert', methods=['POST'])
def push_alert():
    data = request.get_json()
    message = data.get('alert', '')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Avoid duplicate alerts (based on message)
    if not any(alert['message'] == message for alert in alerts):
        alerts.append({'message': message, 'timestamp': timestamp})

    return jsonify({"status": "received"}), 200

@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts)

def clear_alerts_periodically(interval=15):
    while True:
        time.sleep(interval)
        with queue_lock:
            if alerts:
                print(f"[Cleaner] Clearing {len(alerts)} alerts.")
            alerts.clear()

# Start cleaner thread
threading.Thread(target=clear_alerts_periodically, daemon=True).start()

# CURRENTLY NOT USED/BEING CALLED ANYWHERE
@app.route('/clear_alerts', methods=['POST'])
def clear_alerts():
    alerts.clear()
    return jsonify({"status": "cleared"}), 200

if __name__ == '__main__':
    app.run(port=5050)
