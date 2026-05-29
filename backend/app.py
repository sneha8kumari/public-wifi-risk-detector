from flask import Flask, jsonify, request
from flask_cors import CORS
from detector import WiFiDetector

app = Flask(__name__)
CORS(app)

detector = WiFiDetector()
detector.start_monitoring()

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify(detector.get_status())

@app.route('/api/scenario', methods=['POST'])
def trigger_scenario():
    data = request.json
    scenario = data.get('scenario')
    if scenario:
        detector.set_scenario(scenario)
        return jsonify({"status": "success", "scenario": scenario})
    return jsonify({"status": "error", "message": "No scenario provided"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
