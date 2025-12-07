import os
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ================== 公共参数配置 ==================
# 注意：实际应用应使用更安全的参数设置
DEFAULT_PASSWORD = b"my_secret_password"  # 预共享密码
HKDF_SALT = os.urandom(16)  # 随机盐值
INFO = b"PAKE-Demo"  # 上下文信息


# ================== 客户端实现 ==================
class PAKEClient:
    def __init__(self, password):
        self.password = password
        self.client_nonce = os.urandom(16)  # 客户端随机数

    def initiate(self):
        # 发送给服务器的公开信息（模拟网络传输）
        return {
            "client_nonce": self.client_nonce,
            "salt": HKDF_SALT
        }

    def derive_key(self, server_nonce):
        # 组合随机数生成共享密钥
        shared_material = self.client_nonce + server_nonce

        # 使用HKDF进行密钥派生
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=HKDF_SALT,
            info=INFO,
        )
        derived_key = hkdf.derive(self.password + shared_material)

        # 生成验证MAC
        client_mac = hmac.new(derived_key, self.client_nonce, hashlib.sha256).digest()
        return derived_key, client_mac


# ================== 服务端实现 ==================
class PAKEServer:
    def __init__(self, password):
        self.password = password
        self.server_nonce = os.urandom(16)  # 服务端随机数

    def respond(self, client_data):
        # 接收客户端初始数据
        self.client_nonce = client_data["client_nonce"]
        self.salt = client_data["salt"]

        # 返回服务端随机数（模拟网络传输）
        return {"server_nonce": self.server_nonce}

    def verify(self, client_mac, derived_key):
        # 验证客户端MAC
        expected_mac = hmac.new(derived_key, self.client_nonce, hashlib.sha256).digest()
        if not hmac.compare_digest(client_mac, expected_mac):
            raise ValueError("MAC验证失败")

        # 生成服务端MAC（双向验证）
        server_mac = hmac.new(derived_key, self.server_nonce, hashlib.sha256).digest()
        return server_mac


# ================== 协议执行流程 ==================
def main():
    # 初始化双方（假设密码已共享）
    client = PAKEClient(DEFAULT_PASSWORD)
    server = PAKEServer(DEFAULT_PASSWORD)

    # 阶段1：客户端发起请求
    client_init = client.initiate()

    # 阶段2：服务端响应
    server_response = server.respond(client_init)

    # 阶段3：客户端生成密钥并验证
    client_key, client_mac = client.derive_key(server_response["server_nonce"])

    # 阶段4：服务端验证并生成密钥
    try:
        server_mac = server.verify(client_mac, client_key)
        print("客户端验证成功！")
        # 服务端生成相同密钥（演示用）
        print("协商密钥:", client_key.hex())
    except ValueError as e:
        print("认证失败:", str(e))


if __name__ == "__main__":
    main()