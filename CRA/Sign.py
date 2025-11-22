import traceback

from gen_group import *
import time

# p, q, g = gen_p_q_g()
# print(f'p = {p}')
# print(f'q = {q}')
# print(f'g = {g}')
p = 82749193135524678875917031025526633418191968538603911587940360194901606694643
q = 41374596567762339437958515512763316709095984269301955793970180097450803347321
g = 2

def mod_pow(base, exp, mod):
    """模幂运算：base^exp mod mod"""
    return pow(base, exp, mod)


class Signer:
    def __init__(self, signer_id):
        self.id = signer_id
        # self.sk = random.randint(1, q - 1)  # 私钥sk_i ∈ Zq
        self.sk = q - 5
        self.pk = mod_pow(g, self.sk, p)  # 公钥g^x_i
        # self.r = random.randint(1, q - 1)  # 临时私钥r_i ∈ Zq
        self.r = q - 4
        self.R = mod_pow(g, self.r, p)  # 临时公钥R_i = g^r_i

    def sign(self, m_i, R_A):
        """生成签名τ_i = r_i + H(N||m_i) * sk * bk mod q"""
        hash_input = f"{R_A}{m_i}".encode()
        c_i = int(hashlib.sha256(hash_input).hexdigest(), 16) % q
        tau_i = self.r + c_i * self.sk
        return tau_i

def aggregate_signatures(tau_list):
    """聚合签名"""
    tau = sum(tau_list)
    return tau

def generate_D(signer, messages):
    """生成D"""
    D = []
    if messages != "hello world":
        D.append((signer.id, messages, signer.pk))
    return D

def generate_D_1(signer, messages, v):
    """生成D"""
    D = []
    if messages != v:
        D.append((signer.id, messages.hex(), signer.pk))
    return D

def aggregate_tmp_public_keys(signers):
    """聚合临时公钥"""
    # 收集所有临时公钥R_i并计算N
    R_list = [signer.R for signer in signers]
    R_A = 1
    # 计算临时公钥的乘积N = ∏(R_i) mod p
    for R_i in R_list:
        R_A = (R_A * R_i) % p
    return R_A

def aggregate_public_keys(signers):
    """聚合公钥"""
    pk_list = [signer.pk for signer in signers]
    apk = 1
    for pk_i in pk_list:
        apk = (apk * pk_i) % p
    return apk

def verify_signature(tau, R_A, D, apk, M):
    """验证签名：g^τ ≡ N * ∏(upk_i^H(N||m_i)) mod p"""
    try:
        pro_c = 1
        for id, m_i, pk_i in D:
            pro_c = (pro_c * pk_i) % p

        apk_M = (apk * mod_pow(pro_c, -1, p)) % p
        hash_input = f"{R_A}{M}".encode()
        c_M = int(hashlib.sha256(hash_input).hexdigest(), 16) % q
        uapk_M_CM = pow(apk_M, c_M, p)

        product_upk_c = 1
        for id, m_i, upk_i in D:
            hash_input = f"{R_A}{bytes.fromhex(m_i)}".encode()
            c_mi = int(hashlib.sha256(hash_input).hexdigest(), 16) % q
            product_upk_c = (product_upk_c * mod_pow(upk_i, c_mi, p)) % p

        # 右侧R_A * uapk_M ^ CM ∏(upk_i ^ c_mi)
        rhs = (uapk_M_CM * R_A * product_upk_c) % p  # 右侧值
        # 计算左侧：g^τ mod p
        lhs = mod_pow(g, tau, p)
        return lhs == rhs
    except Exception as e:
        # 如果发生异常，打印错误信息
        print(f"发生异常：{e}")
        # 打印详细的异常堆栈信息
        traceback.print_exc()
        return False


# # ----------------- 测试用例 -----------------
# if __name__ == "__main__":
#     start_time = time.time() * 1000
#
#     # 初始化签名者
#     signer1 = Signer(1)
#     signer2 = Signer(2)
#     signer3 = Signer(3)
#     signer4 = Signer(4)
#
#     # with open("usr_bin_hashes.txt", "r") as f:
#     #     usr_bin_hashes = f.readlines()
#     #
#     # # 将当前/usr/bin下所有文件的哈希值赋值给M
#     # M = usr_bin_hashes
#
#     # 定义消息
#     M = "hello world"
#     m = "nihao,shijie"
#     m_1 = "nihuai,shijie"
#
#
#     R_A = aggregate_tmp_public_keys([signer1, signer2, signer3, signer4])
#     # 生成聚合签名
#     # tau, R_A, D = aggregate_signatures([signer1, signer2], M)
#
#     tau_1 = signer1.sign(M, R_A)
#     tau_2 = signer2.sign(M, R_A)
#     tau_3 = signer3.sign(m, R_A)
#     tau_4 = signer4.sign(m_1, R_A)
#     tau_list = [tau_1, tau_2, tau_3, tau_4]
#     tau = aggregate_signatures(tau_list)
#     D_1 = generate_D(signer1, M)
#     D_2 = generate_D(signer2, M)
#     D_3 = generate_D(signer3, m)
#     D_4 = generate_D(signer4, m_1)
#     D = D_1 + D_2 + D_3 + D_4
#     print(D)
#
#     signers = [signer1, signer2, signer3, signer4]
#
#     apk = aggregate_public_keys(signers)
#
#     # 验证签名
#     is_valid = verify(tau, R_A, D, apk, M)
#
#
#     print(f"聚合签名验证结果: {is_valid}")
#
#     end_time = time.time() * 1000
#
#     print(f"运行时间: {end_time - start_time}ms")

    # print("分解验证步骤：")
    # print(f"临时公钥聚合N = {R_A}")
    # print(f"聚合签名τ = {tau}")
    # print(f"验证等式左侧g^τ = {mod_pow(g, tau, p)}")

    # # 手动计算右侧
    # product_upk_c = 1
    # for m_i, upk_i in D:
    #     hash_input = f"{R_A}{m_i}".encode()
    #     c_mi = int(hashlib.sha256(hash_input).hexdigest(), 16) % q
    #     product_upk_c = (product_upk_c * mod_pow(upk_i, c_mi, p)) % p
    # rhs = (uapk_M_1*R_A * product_upk_c) % p
    # print(f"验证等式右侧N*∏(upk_i^c_mi) = {rhs}")