# --------------- 服务端程序 server.py ---------------
from flask import Flask, request, jsonify
import os
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# 模拟数据库存储
stored_password = b"123"
sessions = {}


class PAKEServer:
    def __init__(self, session_id):
        self.session_id = session_id
        self.server_nonce = os.urandom(16)
        self.client_nonce = None
        self.salt = None

    def generate_response(self, client_data):
        self.client_nonce = base64.b64decode(client_data['client_nonce'])
        self.salt = base64.b64decode(client_data['salt'])
        return {
            "server_nonce": base64.b64encode(self.server_nonce).decode(),
            "salt": base64.b64encode(self.salt).decode()
        }

    def verify_client(self, client_mac):
        shared_material = self.client_nonce + self.server_nonce
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=b"PAKE",
        )
        derived_key = hkdf.derive(stored_password + shared_material)

        expected_mac = hmac.new(derived_key, self.client_nonce, hashlib.sha256).digest()
        if not hmac.compare_digest(base64.b64decode(client_mac), expected_mac):
            raise ValueError("客户端MAC验证失败")

        server_mac = hmac.new(derived_key, self.server_nonce, hashlib.sha256).digest()
        return base64.b64encode(server_mac).decode()


@app.route('/initiate', methods=['POST'])
def handle_initiate():
    session_id = os.urandom(8).hex()
    server = PAKEServer(session_id)
    sessions[session_id] = server

    response_data = server.generate_response(request.json)
    return jsonify({
        "session_id": session_id,
        **response_data
    })


@app.route('/verify', methods=['POST'])
def handle_verify():
    session_id = request.json['session_id']
    server = sessions.get(session_id)

    if not server:
        return jsonify({"error": "无效会话ID"}), 400

    try:
        server_mac = server.verify_client(request.json['client_mac'])
        del sessions[session_id]  # 清理会话
        return jsonify({
            "status": "success",
            "server_mac": server_mac
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)