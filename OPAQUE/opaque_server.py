from cryptography.hazmat.primitives.asymmetric import x25519
from flask import Flask, request, jsonify
import opaque_common as common
import base64
import os
import secrets
from collections import defaultdict
import hmac
import hashlib
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
    datefmt='%Y-%m-%d  %H:%M:%S %a'
)
# 创建Flask应用实例
app = Flask(__name__)

users_db = defaultdict(dict)

# 生成服务器端的32字节OPRF密钥
SERVER_OPRF_KEY = os.urandom(32)
# 初始化OPRF实例，使用服务器密钥
server_oprf = common.OPRF(SERVER_OPRF_KEY)

@app.route('/register/init', methods=['POST'])
def register_init():
    """
    处理注册初始化请求
    接收客户端发送的盲化密码哈希，进行OPRF评估并返回结果
    """
    # 解析客户端发送的JSON数据
    data = request.json
    username = data['username']

    # 检查用户是否已存在，避免重复注册
    if username in users_db:
        return jsonify({"error": "User already exists"}), 400

    # 解码客户端发送的盲化元素
    blinded_element = base64.b64decode(data['blinded_element'])
    # 使用服务器OPRF密钥对盲化元素进行评估
    evaluated_element = server_oprf.blind_evaluate(blinded_element)

    # 将评估结果Base64编码后返回给客户端
    return jsonify({
        "evaluated_element": base64.b64encode(evaluated_element).decode()
    })

@app.route('/register', methods=['POST'])
def register_user():
    """
    完成用户注册
    存储客户端发送的公钥和加密信封（包含客户端私钥）
    """
    data = request.json
    username = data['username']

    # 检查用户是否已存在
    if username in users_db:
        return jsonify({"error": "User already exists"}), 400

    # 将用户信息存储到数据库
    users_db[username] = {
        'public_key': data['public_key'],
        'envelope': data['envelope']
    }
    logging.info(f'User {username} registered successfully.')
    return jsonify({"status": "success"})

@app.route('/login/init', methods=['POST'])
def login_init():
    """
    处理登录初始化请求
    验证用户存在，返回OPRF评估结果、存储的信封和服务器临时公钥
    """
    data = request.json
    username = data['username']

    # 检查用户是否存在
    if username not in users_db:
        return jsonify({"error": "User not found"}), 404

    # 从数据库获取用户信封并解码
    envelope = base64.b64decode(users_db[username]['envelope'])
    # 解码客户端发送的盲化元素
    blinded_element = base64.b64decode(data['blinded_element'])
    # 对盲化元素进行OPRF评估
    evaluated_element = server_oprf.blind_evaluate(blinded_element)

    # 生成服务器端临时X25519密钥对
    server_private_key = x25519.X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()

    # 生成会话ID，用于标识本次登录会话
    session_id = secrets.token_urlsafe(16)
    # 存储会话信息到数据库
    users_db[username]['session'] = {
        'session_id': session_id,
        'server_private_key': server_private_key,  # 服务器临时私钥
        'client_public_key': None,  # 后续存储客户端临时公钥
        'shared_secret': None  # 后续存储密钥交换后的共享秘密
    }

    # 返回会话信息给客户端
    return jsonify({
        "session_id": session_id,
        "evaluated_element": base64.b64encode(evaluated_element).decode(),
        "envelope": base64.b64encode(envelope).decode(),
        "server_public_key": base64.b64encode(
            common.serialize_public_key(server_public_key)  # 序列化公钥为字节
        ).decode()
    })

@app.route('/login/finish', methods=['POST'])
def login_finish():
    """
    完成登录流程
    进行密钥交换，生成会话密钥，加密命令并返回给客户端
    """
    data = request.json
    username = data['username']
    session_id = data['session_id']

    # 验证会话有效性
    if username not in users_db or 'session' not in users_db[username]:
        return jsonify({"error": "Invalid session"}), 400

    session_data = users_db[username]['session']
    # 验证会话ID是否匹配
    if session_data['session_id'] != session_id:
        return jsonify({"error": "Session mismatch"}), 400
    logging.info(f'login_finish called for user: {username}, session_id: {session_id}')

    # 解码并反序列化客户端临时公钥
    client_public_key = common.deserialize_public_key(
        base64.b64decode(data['client_public_key'])
    )
    session_data['client_public_key'] = client_public_key

    # 使用服务器临时私钥与客户端临时公钥进行密钥交换
    server_private_key = session_data['server_private_key']
    shared_secret = server_private_key.exchange(client_public_key)
    session_data['shared_secret'] = shared_secret
    logging.info(f'Shared secret: {shared_secret.hex()}')

    # 从共享秘密使用HKDF派生会话密钥
    session_key = common.derive_keys(shared_secret, b"OPAQUE_SESSION_KEY")[:32]
    logging.info(f"Session key: {session_key.hex()}")

    # 准备要发送给客户端的命令
    command = b"run update"
    logging.info(f'Command to encrypt: {command}')
    # 使用会话密钥加密命令，AES-GCM模式
    ciphertext = common.encrypt_aes_gcm(session_key, command)
    logging.info(f'Commands Ciphertext: {ciphertext.hex()}')

    # 计算HMAC用于验证消息完整性和真实性
    auth_message = hmac.new(session_key, ciphertext, hashlib.sha256).digest()
    logging.info(f'Auth message: {auth_message.hex()}')

    # 清除会话信息
    del users_db[username]['session']

    # 返回加密的命令和认证信息
    return jsonify({
        "status": "success",
        "auth_message": base64.b64encode(auth_message).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
