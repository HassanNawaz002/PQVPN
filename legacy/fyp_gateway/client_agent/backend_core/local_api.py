# fyp_gateway/client_agent/backend_core/local_api.py

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# AWS Control Plane Gateway Target
AWS_SERVER_IP = "107.21.77.85"
AWS_CONTROL_PLANE_URL = f"http://{AWS_SERVER_IP}:8001/api/v1/gateway/handshake"

# CORS Headers allow karne ke liye
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

@app.route('/v1/client/privileges', methods=['GET'])
def check_privileges():
    return jsonify({"is_privileged": True, "diagnostic_msg": "Local Core Active"}), 200

@app.route('/api/v1/client/connect', methods=['POST', 'OPTIONS'])
def trigger_handshake():
    if request.method == 'OPTIONS':
        return '', 200

    try:
        payload = {
            "client_id": "win_client_node_01",
            "ephemeral_x25519_pub": "sample_x25519_key",
            "ephemeral_mlkem_pub": "sample_mlkem_key",
            "mldsa_signature": "sample_mldsa_sig"
        }

        print(f"[*] Dispatching PQC Handshake request to AWS Server: {AWS_CONTROL_PLANE_URL}")
        
        # Dispatching request to AWS Gateway
        response = requests.post(AWS_CONTROL_PLANE_URL, json=payload, timeout=10)

        if response.status_code == 200:
            return jsonify({
                "status": "success",
                "message": "Handshake verified by AWS Gateway",
                "data": response.json()
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": f"AWS Gateway returned HTTP {response.status_code}"
            }), response.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({
            "status": "error",
            "message": f"Could not reach AWS Gateway at {AWS_SERVER_IP}:8001"
        }), 503
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    print(f"[*] Local Client Backend Service running on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)