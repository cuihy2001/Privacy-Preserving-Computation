# mqtt_server.py - 运行在树莓派A上
import paho.mqtt.client as mqtt
from Sign import *
import ast
import threading
import logging
import json
from TokenIssue import *
from charset_normalizer import from_bytes
from scipy.constants import sigma

logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')

network_owner = NetworkOwnerO()

# 参数设置
BROKER_IP = "192.168.3.128"  # A的IP
CLIENT_IP = "192.168.3.127"   # 当前设备的IP
# PROVER_IP = "192.168.3.126"  # 证明者的IP
# PROVER_IP_1 = "192.168.3.144"
# A_2_IP = "192.168.3.139"
# A_3_IP = "192.168.3.140"
TOPIC_ALL = "rpi/all"        # 广播频道
TOPIC_SERVER = "rpi/server/owner"   # 接收客户端消息的频道
TOPIC_CLIENT = f"rpi/client/{CLIENT_IP}"  # 当前客户端的专属频道
# TOPIC_PROVER = f"rpi/client/{PROVER_IP}"  # 当前证明者的专属频道
# TOPIC_PROVER_1 = f"rpi/client/{PROVER_IP_1}"  # 当前证明者的专属频道
TOPIC_A_2 = "rpi/server/2"  # 接收证明者消息的频道
TOPIC_A_3 = "rpi/server/3"  # 接收证明者消息的频道

# 全局状态控制
R_TIMEOUT = 3              # 3秒超时
R_collecting = False       # 是否正在收集R_i
a_collecting = False
R_timer = None             # 超时计时器
num_leaf_R = 2  # 叶子节点数量
num_leaf_a = 2
R_sent = False

# 全局变量
N_V = b''
delta_t = 0

# 聚合器角色全局变量
R_A = 0  # 聚合承诺
R_list = []  # 临时公钥列表
PK_P_list = []  # 公钥列表
tau_list = []  # tau列表
D_list = []
ids = [] # 签名者ID列表
I_list = [1,2] # 初始化所有签名者ID列表
H = ["configure1", "configure2", "configure3"]
h = ["configure3"]

def on_connect(client, userdata, flags, rc):
    logging.info("Server connected to Broker!")

    client.subscribe(TOPIC_SERVER)
    # client.subscribe(TOPIC_ALL)
    PK_O = network_owner.pk_o.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    message = {
        "type": "PK_O",
        "PK": PK_O.hex(),
    }
    client.publish(TOPIC_ALL, json.dumps(message))

def on_message(client, userdata, msg):
    global tau, R_A, apk, R_collecting, R_timer, ids, I_list, N_O, pk_v, bf, a_collecting, a_timer
    if msg.topic == TOPIC_SERVER:
        # logging.info(f"\n[From Client] {msg.payload.decode()}\nEnter broadcast message: ", end="")

        msg_type = json.loads(msg.payload.decode())["type"]
        data = json.loads(msg.payload.decode())
        if msg_type == "PK_V":
            logging.info("从节点接收到 PK 消息.")
            pk_v = serialization.load_der_public_key(
                bytes.fromhex(data["PK"]),
                backend=default_backend()
            )
            N_O = network_owner.generate_nonce()
            message = {
                "type": "N_O",
                "N_O": N_O.hex(),
            }
            client.publish(TOPIC_CLIENT, json.dumps(message))

        if msg_type == "PK_P":
            logging.info("从节点接收到 PK_P 消息.")
            PK_P = data["PK_P"]
            PK_P_list.append(PK_P)
            apk = aggregate_tmp_public_keys(PK_P_list)
            logging.info(f'当前聚合公钥: {apk}')


        if msg_type == "T_request":
            logging.info("从节点接收到 T_request 消息.")
            delta_t = data["delta_t"]
            delta_t_prime = network_owner.check_policy(delta_t)
            sigma_V = bytes.fromhex(data["sigma_V"])
            if delta_t_prime != 0 and network_owner.verify_signature(
                    pk_v,
                    N_O + str(delta_t).encode(),
                    sigma_V
            ):
                logging.info(f'初始验证成功，时间增量为 {delta_t_prime} 秒')
                # 生成令牌组件
                c_l, v_l = network_owner.get_free_counter()
                configs = network_owner.get_good_configs()
                bf = network_owner.insert_bloom_filter(configs).bitarray
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
                logging.info(f"令牌生成成功: {T}")
                # 获取ID并加密令牌
                I = network_owner.get_ids()
                encrypted_T = network_owner.encrypt_token(pk_v, T)
                # 对随机数、APK和ID进行签名
                sigma = network_owner.sign_nonce_apk_ids(N_V, network_owner.apk, ids)

                message = {
                    "type": "T_response",
                    "encrypted_T": encrypted_T,
                    "sigma": sigma.hex(),
                    "ids": I,
                }
                client.publish(TOPIC_CLIENT, json.dumps(message))
            else:
                print("策略检查或初始验证失败")

        if msg_type == "Ch":
            logging.info("从节点接收到 Ch 消息.")
            t =  int(time.time())
            # 现在验证者和网络所有者为一体，BF赋值为bf
            BFValue = bf
            if data['T']['T_exp'] < t:
                logging.info("令牌已过期，协议终止")
                return
            elif not network_owner.verify_signature(
                network_owner.pk_o,
                str(BFValue).encode() + str(data['T']['c_l']).encode() + str(data['T']['v_l']).encode() + str(data['T']['T_exp']).encode(),
                base64.b64decode(data['T']['sigma_O'])
            ):
                logging.info("令牌签名验证失败，协议终止")
                return
            else:
                logging.info("令牌签名验证成功，开始协议")
                # 发送data
                client.publish(TOPIC_A_2, json.dumps(data))
                client.publish(TOPIC_A_3, json.dumps(data))

        if msg_type == "R_i":
            # 如果是第一条R_i，启动计时器
            if not R_collecting:
                R_collecting = True
                logging.info("开始收集 R_i (3-second 空窗)...")

                # 设置3秒后超时
                def timeout_action():
                    global R_A, I_list, R_sent
                    if R_sent:
                        return
                    R_sent = True
                    logging.info("超时! 开始聚合当前 R_list.")
                    R_A = aggregate_tmp_public_keys(R_list)
                    # 发送聚合结果
                    message = {
                        "type" : 'R_A',
                        "R_A" : R_A
                    }

                    client.publish(TOPIC_ALL, json.dumps(message))
                    # 计算I_list和ids的差集
                    I_list = list(set(I_list) - set(ids))
                    logging.info(f'未进行承诺的签名者ID（可能已经掉线）: {I_list}')


                R_timer = threading.Timer(R_TIMEOUT, timeout_action)
                R_timer.start()

                # 只有处于收集状态时才处理
            if R_collecting:
                R_i = data['R_i']
                id = data['id']
                ids.append(id)
                R_list.append(R_i)
                logging.info(f"已接收 R_{id}: {R_i} (总计: {len(R_list)}/{num_leaf_R})")

                # 检查是否收满
                if len(R_list) == num_leaf_R and not R_sent:
                    R_collecting = False
                    if R_timer:
                        R_timer.cancel()  # 取消计时器
                    R_A = aggregate_tmp_public_keys(R_list)
                    message = {
                        "type" : 'R_A',
                        "R_A" : R_A
                    }
                    client.publish(TOPIC_ALL, json.dumps(message))
                    logging.info(f"已收集共 {num_leaf_R} 条R_i messages.")
                    logging.info(f'所有签名者均已进行承诺.')

        if msg_type == "a_i":
            # 处理D消息
            D_i = data['D']
            # logging.info(f'当前D_i: {D_i}')
            if D_i:
                for d in D_i:
                    D_list.append(tuple(d))
            # 如果是第一条a_i，启动计时器
            if not a_collecting:
                a_collecting = True
                logging.info("开始收集 a_i (3-second 空窗)...")

                # 设置3秒后超时
                def timeout_action():
                    global tau
                    logging.info("超时! 开始聚合当前 tau_list.")
                    tau = aggregate_signatures(tau_list)
                    logging.info(f'当前Dlist: {D_list}')
                    logging.info(f'当前tau: {tau}')
                    M = bf
                    is_valid = verify_signature(tau, R_A, D_list, apk, M)
                    logging.info(f'R_A:{R_A}')
                    logging.info(f'apk:{apk}')
                    logging.info(f"聚合签名验证结果: {is_valid}")
                    # 发送聚合结果
                    message = {
                        "type": "res",
                        "a_i": tau,
                        "ids": ids,
                        "h_1": h,
                        "D": D_list,
                        "apk": apk
                    }

                    client.publish(TOPIC_CLIENT, json.dumps(message))


                a_timer = threading.Timer(R_TIMEOUT, timeout_action)
                a_timer.start()

                # 只有处于收集状态时才处理
            if a_collecting:
                logging.info("从节点接收到 a_i 消息.")
                tau_i = data['a_i']
                tau_list.append(tau_i)
                logging.info(f"已接收 tau_i: {tau_i} (总计: {len(tau_list)}/{num_leaf_a})")

                # 检查是否收满
                if len(tau_list) == num_leaf_a:
                    a_collecting = False
                    if a_timer:
                        a_timer.cancel()  # 取消计时器
                    tau = aggregate_signatures(tau_list)
                    logging.info(f'当前Dlist: {D_list}')
                    logging.info(f'当前tau: {tau}')
                    M = bf
                    is_valid = verify_signature(tau, R_A, D_list, apk, M)
                    logging.info(f"聚合签名验证结果: {is_valid}")
                    message = {
                        "type": "res",
                        "a_i": tau,
                        "ids": ids,
                        "h_1": h,
                        "D": D_list,
                        "apk": apk
                    }
                    client.publish(TOPIC_CLIENT, json.dumps(message))
                    logging.info(f"已收集共 {num_leaf_a} 条a_i messages.")


            # logging.info("从节点接收到 a_i 消息.")
            # tau = data['a_i']


            # tau_list.append(tau_i)
            # logging.info(f'当前tau_list: {tau_list}')
            # if len(tau_list) > num_leaf:
            #     tau_list.pop(0)
            # elif len(tau_list) == len(R_list):
            #     tau = aggregate_signatures(tau_list)
            #     logging.info(f'当前tau_list: {tau_list}')
            # M = bf
            # if len(tau_list) == len(R_list):
            #     logging.info(f'当前tau_list: {tau_list}')
            #     logging.info(f'当前D_list: {D_list}')
            #     tau = aggregate_signatures(tau_list)
            # is_valid = verify(tau, R_A, D_list , apk, M)
            # logging.info(f"聚合签名验证结果: {is_valid}")
            # message = {
            #     "type": "res",
            #     "a_i": tau,
            #     "ids": ids,
            #     "h_1": h,
            #     "D": D_list,
            #     "apk": apk
            # }
            # client.publish(TOPIC_CLIENT, json.dumps(message))

    # if msg.topic == TOPIC_ALL:
    #     # logging.info(f"\n[From Client] {msg.payload.decode()}\nEnter broadcast message: ", end="")
    #
    #     msg_type = json.loads(msg.payload.decode())["type"]
    #     data = json.loads(msg.payload.decode())
    #     if msg_type == "PK_V":
    #         logging.info("从节点接收到 PK 消息.")
    #         pk_v = serialization.load_der_public_key(
    #             bytes.fromhex(data["PK"]),
    #             backend=default_backend()
    #         )
    #         N_O = network_owner.generate_nonce()
    #         message = {
    #             "type": "N_O",
    #             "N_O": N_O.hex(),
    #         }
    #         client.publish(TOPIC_CLIENT, json.dumps(message))







def aggregate_tmp_public_keys(R_list):
    """聚合临时公钥"""
    # 收集所有临时公钥R_i并计算N
    R_A = 1
    # 计算临时公钥的乘积N = ∏(R_i) mod p
    for R_i in R_list:
        R_A = (R_A * R_i) % p
    return R_A

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER_IP, 1883, 60)

# 启动消息循环
client.loop_start()

while True:
    message = input("Enter broadcast message (or 'exit'): ")
    if message.lower() == 'exit':
        break
    # client.publish(TOPIC_ALL, f"{message}")

client.disconnect()
