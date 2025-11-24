import base64
import os
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from pybloom_live import ScalableBloomFilter, BloomFilter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import json
from Sign import *


# 维护全局变量c_l、v_l以及计数器生成列表
c_l = 0
v_l = 0
c_l_list = [] # 计数器生成列表

class VerifierV:
    def __init__(self):
        # 生成验证者的密钥对
        self.sk_v = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.pk_v = self.sk_v.public_key()
        self.cert_pk_v = "验证者证书"

    def generate_nonce(self, length=32):
        """生成随机数"""
        return os.urandom(length)

    def sign_delta_t(self, N_O, delta_t):
        """对随机数和时间增量进行签名"""
        message = N_O + str(delta_t).encode()
        signature = self.sk_v.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def decrypt_token(self, encrypted_data):
        """解密接收到的令牌"""
        try:
            if isinstance(encrypted_data, dict):
                # 处理混合加密情况
                # 解密AES密钥
                aes_key = self.sk_v.decrypt(
                    bytes.fromhex(encrypted_data['encrypted_key']),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # 解密实际数据
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(bytes.fromhex(encrypted_data['iv'])))
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(bytes.fromhex(encrypted_data['ciphertext'])) + decryptor.finalize()

                # 去除填充
                unpadder = sym_padding.PKCS7(128).unpadder()
                token_json = unpadder.update(padded_data) + unpadder.finalize()
            else:
                # 普通RSA解密
                token_json = self.sk_v.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

            import json
            return json.loads(token_json.decode('utf-8'))
        except Exception as e:
            print(f"解密失败: {str(e)}")
            raise


class NetworkOwnerO:
    def __init__(self):
        # 生成网络所有者的密钥对
        self.sk_o = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.pk_o = self.sk_o.public_key()
        self.apk = "接入点密钥"
        self.cert_pk_o = "网络所有者证书"
        self.token_store = {}  # 令牌存储

    def generate_nonce(self, length=32):
        """生成随机数"""
        return os.urandom(length)

    def check_policy(self, delta_t):
        """检查时间增量是否符合策略"""
        if 1 <= delta_t <= 3600:  # 简单策略：1秒到1小时之间
            return delta_t
        return 0

    def get_free_counter(self):
        """获取空闲计数器（模拟实现）"""
        global c_l, v_l, c_l_list
        c_l += 1
        c_l_list.append((c_l, v_l))
        return (c_l, v_l)  # (计数器, 值)

    def get_good_configs(self):
        """获取良好配置（模拟实现）"""
        return ["configure1", "configure2", "configure3"]

    def insert_bloom_filter(self, configs):
        """创建布隆过滤器"""
        bf = BloomFilter(capacity=100, error_rate=0.001)
        for config in configs:
            bf.add(config)
        # 返回bf

        return bf

    def get_current_time(self):
        """获取当前时间"""
        return int(time.time())

    def sign_bloom_filter(self, bf_value, c_l, v_l, T_exp):
        """对布隆过滤器及相关数据进行签名"""
        message = str(bf_value).encode() + str(c_l).encode() + str(v_l).encode() + str(T_exp).encode()
        signature = self.sk_o.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def get_ids(self):
        """获取ID（模拟实现）"""
        return [1, 2, 3, 4]

    def encrypt_token(self, pk_v, token):
        """使用验证者公钥加密令牌"""
        try:

            # 更安全的序列化方式
            token_json = json.dumps(token, separators=(',', ':')).encode('utf-8')

            # 数据长度检查
            max_length = (pk_v.key_size // 8) - 66
            if len(token_json) > max_length:
                # 如果数据太长，使用混合加密方案
                # 生成随机的AES密钥
                aes_key = os.urandom(32)
                iv = os.urandom(16)

                # 用AES加密实际数据
                padder = sym_padding.PKCS7(128).padder()
                padded_data = padder.update(token_json) + padder.finalize()
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()

                # 用RSA加密AES密钥
                encrypted_key = pk_v.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # 将上述内容转换成字符串


                return {'encrypted_key': encrypted_key.hex(), 'iv': iv.hex(), 'ciphertext': ciphertext.hex()}

            # 普通情况：直接RSA加密
            return pk_v.encrypt(
                token_json,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"加密失败: {str(e)}")
            raise

    def sign_nonce_apk_ids(self, N_V, apk, ids):
        """对随机数、APK和ID进行签名"""
        message = N_V + apk.encode() + str(ids).encode()
        signature = self.sk_o.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, pk, message, signature):
        """验证签名"""
        try:
            pk.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def store_token(self, apk, ids, token):
        """存储令牌"""
        self.token_store[(apk, tuple(ids))] = token



def main():
    # 初始化双方
    verifier = VerifierV()
    network_owner = NetworkOwnerO()

    # 步骤1：验证者生成随机数和签名
    N_V = verifier.generate_nonce()
    delta_t = 3600  # 1小时
    N_O = network_owner.generate_nonce()
    sigma_V = verifier.sign_delta_t(N_O, delta_t)

    # 步骤2：网络所有者生成令牌
    delta_t_prime = network_owner.check_policy(delta_t)
    if delta_t_prime != 0 and network_owner.verify_signature(
            verifier.pk_v,
            N_O + str(delta_t).encode(),
            sigma_V
    ):
        print(f'初始验证成功，时间增量为 {delta_t_prime} 秒')
        # 生成令牌组件
        c_l, v_l = network_owner.get_free_counter()
        c_l_1, v_l_1 = network_owner.get_free_counter()
        print(c_l_list)
        configs = network_owner.get_good_configs()
        bf = network_owner.insert_bloom_filter(configs)
        # 将布隆过滤器转换为值
        current_time = network_owner.get_current_time()
        T_exp = current_time + delta_t_prime

        # 对布隆过滤器数据进行签名
        sigma_O = network_owner.sign_bloom_filter(str(bf), c_l, v_l, T_exp)

        # 创建令牌
        T = {
            'T_exp': T_exp,
            'c_l': c_l,
            'v_l': v_l,
            'H': configs,
            'sigma_O': base64.b64encode(sigma_O).decode('utf-8')  # 将签名转为base64字符串
        }
        print(f"生成的令牌: {T}")
        # 获取ID并加密令牌
        ids = network_owner.get_ids()
        encrypted_T = network_owner.encrypt_token(verifier.pk_v, T)

        # 对随机数、APK和ID进行签名
        sigma = network_owner.sign_nonce_apk_ids(N_V, network_owner.apk, ids)

        # 步骤3：存储令牌（实际应用中会发送给验证者）
        if network_owner.verify_signature(
                network_owner.pk_o,
                N_V + network_owner.apk.encode() + str(ids).encode(),
                sigma
        ):
            # 实际应用中，验证者会解密并验证

            if network_owner.verify_signature(
                    network_owner.pk_o,
                    str(bf).encode() + str(c_l).encode() + str(v_l).encode() + str(T_exp).encode(),
                    sigma_O
            ):
                decrypted_T = verifier.decrypt_token(encrypted_T)
                # print(type(encrypted_T['encrypted_key']))
                # print(type(encrypted_T['iv']))
                # print(type(encrypted_T['ciphertext']))




                network_owner.token_store = decrypted_T
                print("令牌生成并存储成功！")
            else:
                print("令牌签名验证失败")
        else:
            print("初始签名验证失败")
    else:
        print("策略检查或初始验证失败")

    # 步骤4：执行认证

    N = os.urandom(32)
    ids_1 = []
    Ch = {
        'N': N,
        'T': network_owner.token_store,
        'ids_1': ids_1
    }

    # 发送给聚合器
    t = int(time.time())
    BFValue = bf
    if Ch['T']['T_exp'] < t:
        print("令牌已过期，协议终止")
    elif not network_owner.verify_signature(
                    network_owner.pk_o,
                    str(BFValue).encode() + str(Ch['T']['c_l']).encode() + str(Ch['T']['v_l']).encode() + str(Ch['T']['T_exp']).encode(),
                    base64.b64decode(Ch['T']['sigma_O'].encode('utf-8'))
            ):
        print("令牌签名验证失败")
    else:
        H = configs
        h = ["nihao,shijie"]
        h_1 = ["nihuai,shijie"]

        # 初始化签名者
        signer1 = Signer(1)
        signer2 = Signer(2)
        signer3 = Signer(3)
        signer4 = Signer(4)
        signers = [signer1, signer2, signer3, signer4]

        for signer in signers:
            ids_1.append(signer.id)
        R_A = aggregate_tmp_public_keys(signers)
        bfValue = network_owner.insert_bloom_filter(h)
        bfValue_1 = network_owner.insert_bloom_filter(h_1)

        if h in H:
            bfValue = BFValue
        M = BFValue.bitarray
        print(f'M: {M}')
        m = str(bfValue).encode() + N + str(v_l).encode() + str(c_l).encode()
        m_1 = str(bfValue_1).encode() + N + str(v_l_1).encode() + str(c_l_1).encode()
        tau_1 = signer1.sign(M, R_A)
        tau_2 = signer2.sign(M, R_A)
        tau_3 = signer3.sign(m, R_A)
        tau_4 = signer4.sign(m_1, R_A)
        tau_list = [tau_1, tau_2, tau_3, tau_4]
        tau = aggregate_signatures(tau_list)

        D_1 = generate_D_1(signer1, M, M)
        D_2 = generate_D_1(signer2, M, M)
        D_3 = generate_D_1(signer3, m, M)
        D_4 = generate_D_1(signer4, m_1, M)
        D = D_1 + D_2 + D_3 + D_4
        print(D)
        apk = aggregate_public_keys(signers)
        # 验证签名
        is_valid = verify_signature(tau, R_A, D, apk, M)
        if is_valid:
            print("聚合签名验证成功！")
        else:
            print("聚合签名验证失败！")
        print(ids)
        print(ids_1)




if __name__ == "__main__":
    main()
    H = ["configure1", "configure2", "configure3"]
    h = ["configure1"]
    if all(item in H for item in h):
        print(f'配置良好')
    else:
        print(f'配置不良好')