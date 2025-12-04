# --------------- 客户端程序 client.py ---------------
import requests
import os
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SERVER_URL = "http://127.0.0.1:5000"


class PAKEClient:
    def __init__(self, password):
        self.password = password
        self.client_nonce = os.urandom(16)
        self.salt = os.urandom(16)
        self.session_id = None
        self.server_nonce = None

    def initiate_session(self):
        response = requests.post(
            f"{SERVER_URL}/initiate",
            json={
                "client_nonce": base64.b64encode(self.client_nonce).decode(),
                "salt": base64.b64encode(self.salt).decode()
            }
        ).json()

        self.session_id = response['session_id']
        self.server_nonce = base64.b64decode(response['server_nonce'])
        self.salt = base64.b64decode(response['salt'])

    def derive_key(self):
        shared_material = self.client_nonce + self.server_nonce
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=b"PAKE",
        )
        self.derived_key = hkdf.derive(self.password + shared_material)

        self.client_mac = hmac.new(self.derived_key, self.client_nonce, hashlib.sha256).digest()
        return base64.b64encode(self.client_mac).decode()

    def verify_server(self, server_mac):
        expected_mac = hmac.new(self.derived_key, self.server_nonce, hashlib.sha256).digest()
        return hmac.compare_digest(base64.b64decode(server_mac), expected_mac)


def main():
    password = input("请输入密码: ").encode()

    client = PAKEClient(password)

    try:
        print("步骤1: 初始化会话...")
        client.initiate_session()

        print("步骤2: 生成验证MAC...")
        client_mac = client.derive_key()

        print("步骤3: 验证服务端...")
        response = requests.post(
            f"{SERVER_URL}/verify",
            json={
                "session_id": client.session_id,
                "client_mac": client_mac
            }
        ).json()

        if response.get('status') == "success":
            if client.verify_server(response['server_mac']):
                print("\n认证成功！协商密钥:", client.derived_key.hex())
            else:
                print("服务端MAC验证失败")
        else:
            print("认证失败:", response.get('error', '未知错误'))
    except Exception as e:
        print("发生错误:", str(e))


if __name__ == '__main__':
    main()