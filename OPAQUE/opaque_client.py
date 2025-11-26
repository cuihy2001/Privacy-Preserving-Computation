import requests
from cryptography.hazmat.primitives import serialization
import hashlib
import opaque_common as common
import base64
import os
from cryptography.hazmat.primitives.asymmetric import x25519
import secrets
import json
import hmac
import hashlib
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
    datefmt='%Y-%m-%d  %H:%M:%S %a'
)

SERVER_URL = "http://localhost:5000"


def hash_password(password: bytes):
    """对密码进行SHA256哈希处理，作为OPRF的输入"""
    return hashlib.sha256(password).digest()


class OPAQUEClient:

    def __init__(self, username, password):
        """初始化客户端实例，存储用户凭证并初始化状态变量"""
        self.username = username  # 用户名
        self.password = password.encode()
        self.private_key = None  # 客户端长期私钥
        self.public_key = None  # 客户端长期公钥
        self.envelope = None  # 加密的密钥信封
        self.oprf_output = None  # OPRF协议输出结果
        self.session_id = None  # 会话标识
        self.session_key = None  # 最终协商的会话密钥

    def register(self):
        """执行注册流程，向服务器注册用户凭证"""
        # 生成客户端长期X25519密钥对
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # 对密码进行盲化元素
        self.blinded_element = hash_password(self.password)

        # 发送用户名和盲化元素到服务器，获取OPRF评估结果
        response = requests.post(
            f"{SERVER_URL}/register/init",
            json={
                "username": self.username,
                "blinded_element": base64.b64encode(self.blinded_element).decode()
            }
        ).json()

        if "error" in response:
            raise Exception(response["error"])

        # 解码服务器返回的OPRF评估结果
        evaluated_element = base64.b64decode(response["evaluated_element"])
        self.oprf_output = evaluated_element

        # 从OPRF输出派生密钥材料
        key_material = common.derive_keys(self.oprf_output, b"OPAQUE_ENVELOPE_KEY")
        encryption_key = key_material[:32]

        # 序列化客户端私钥
        private_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        # 序列化客户端公钥
        public_key_bytes = common.serialize_public_key(self.public_key)
        # 将私钥和公钥拼接作为信封数据
        envelope_data = private_key_bytes + public_key_bytes
        # 使用AES-GCM加密信封数据
        self.envelope = common.encrypt_aes_gcm(encryption_key, envelope_data)

        # 第二步：发送公钥和加密信封到服务器，完成注册
        response = requests.post(
            f"{SERVER_URL}/register",
            json={
                "username": self.username,
                "public_key": base64.b64encode(public_key_bytes).decode(),
                "envelope": base64.b64encode(self.envelope).decode()
            }
        )
        return response.json()

    def login(self):
        """执行登录流程，完成身份验证并获取会话密钥"""
        # 对密码进行哈希处理
        blinded_element = hash_password(self.password)

        # 发送用户名和盲化元素到服务器，初始化登录
        response = requests.post(
            f"{SERVER_URL}/login/init",
            json={
                "username": self.username,
                "blinded_element": base64.b64encode(blinded_element).decode()
            }
        ).json()

        # 处理服务器返回的错误信息
        if "error" in response:
            raise Exception(response["error"])

        # 保存会话ID和服务器返回的OPRF评估结果
        self.session_id = response["session_id"]
        evaluated_element = base64.b64decode(response["evaluated_element"])
        self.oprf_output = evaluated_element

        # 解码服务器返回的加密信封
        encrypted_envelope = base64.b64decode(response["envelope"])
        # 派生解密密钥
        key_material = common.derive_keys(self.oprf_output, b"OPAQUE_ENVELOPE_KEY")
        decryption_key = key_material[:32]

        logging.info(f'Session ID:{self.session_id}')
        logging.info(f'Received evaluated_element:{evaluated_element.hex()}')
        logging.info(f'Received envelope:{encrypted_envelope.hex()}')

        # 解密信封获取客户端私钥
        try:
            envelope_data = common.decrypt_aes_gcm(decryption_key, encrypted_envelope)
        except Exception as e:
            raise Exception("Failed to decrypt envelope: " + str(e))

        # 从信封数据中提取私钥
        private_key_bytes = envelope_data[:32]
        self.private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

        # 反序列化服务器临时公钥
        server_public_key = common.deserialize_public_key(
            base64.b64decode(response["server_public_key"])
        )

        # 生成客户端临时X25519密钥对
        client_private_key = x25519.X25519PrivateKey.generate()
        client_public_key = client_private_key.public_key()
        # 执行ECDH密钥交换，计算共享秘密
        shared_secret = client_private_key.exchange(server_public_key)
        logging.info(f'Shared secret: {shared_secret.hex()}')
        # 从共享秘密派生会话密钥
        session_key = common.derive_keys(shared_secret, b"OPAQUE_SESSION_KEY")[:32]
        self.session_key = session_key

        # 生成随机认证消息
        auth_message = os.urandom(16)

        # 发送客户端临时公钥和会话ID，完成登录
        response = requests.post(
            f"{SERVER_URL}/login/finish",
            json={
                "username": self.username,
                "session_id": self.session_id,
                "client_public_key": base64.b64encode(
                    common.serialize_public_key(client_public_key)
                ).decode(),
                "auth_message": base64.b64encode(auth_message).decode()
            }
        ).json()

        # 验证服务器返回的状态
        if response.get("status") != "success":
            raise Exception("Authentication failed")

        # 解码服务器返回的加密命令和HMAC
        ciphertext = base64.b64decode(response["ciphertext"])
        logging.info(f"Received ciphertext: {ciphertext.hex()}")
        received_hmac = base64.b64decode(response["auth_message"])
        logging.info(f"Received HMAC: {received_hmac.hex()}")

        # 验证HMAC
        calc_hmac = hmac.new(session_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(received_hmac, calc_hmac):
            raise Exception("HMAC verification failed")  # HMAC不匹配可能意味着密钥错误或消息被篡改

        # 解密服务器发送的命令
        command = common.decrypt_aes_gcm(session_key, ciphertext)
        logging.info(f"Received secure command: {command.decode()}")
        return session_key


def main():
    """客户端交互主函数，获取用户输入并执行注册/登录操作"""
    username = input("Enter username: ")
    password = input("Enter password: ")
    action = input("Register or Login? (r/l): ").strip().lower()

    # 创建客户端实例
    client = OPAQUEClient(username, password)

    # 根据用户选择执行注册或登录
    if action == 'r':
        logging.info(f"Registering user...")
        result = client.register()
        logging.info(f"Registration result: {result['status']}")
    elif action == 'l':
        logging.info("Logging in...")
        try:
            session_key = client.login()
            logging.info("Authentication successful!")
            logging.info(f"Session key: {session_key.hex()}")
        except Exception as e:
            print(f"Authentication failed: {str(e)}")
    else:
        print("Invalid action")


if __name__ == '__main__':
    main()
