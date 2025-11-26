# mqtt_client.py - 运行在B/C/D上
import paho.mqtt.client as mqtt
import threading
from no_upk import *
import logging
from Function.TokenIssue import *
import time

logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')

verifier = VerifierV()


def insert_bloom_filter(configs):
    """创建布隆过滤器"""
    bf = BloomFilter(capacity=100, error_rate=0.001)
    for config in configs:
        bf.add(config)
    # 返回bf

    return bf

# 配置（每个客户端需要修改）
BROKER_IP = "192.168.3.128"  # A的IP
CLIENT_IP = "192.168.3.127"   # 当前设备的IP
TOPIC_ALL = "rpi/all"
TOPIC_SERVER = "rpi/server/owner"
TOPIC_CLIENT = f"rpi/client/{CLIENT_IP}"  # 当前客户端的专属频道

# 全局变量
H = ["configure1", "configure2", "configure3"]
BFValue = insert_bloom_filter(H).bitarray
N_O = b''
delta_t = 3600  # 1小时
decrypted_T = {}
I_list = []
S_t = [] # 未签名者集合
R_A = 0
S_attack = [] # 受攻击者集合

def on_connect(client, userdata, flags, rc):
    global start_time
    print("Connected to Server!")
    client.subscribe(TOPIC_ALL)      # 订阅广播
    client.subscribe(TOPIC_CLIENT)   # 订阅自己的专属频道
    N_V = verifier.generate_nonce()
    PK = verifier.pk_v.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    message = {
        "type": 'PK_V',
        "PK": PK.hex(),
        "N_V": N_V.hex()
    }
    message_json = json.dumps(message)
    start_time = time.time()
    client.publish(TOPIC_SERVER, message_json)  # 向服务器发送连接消息

def on_message(client, userdata, msg):
    global N_O, delta_t, decrypted_T, I_list, S_t, R_A, S_attack
    if msg.topic == TOPIC_CLIENT:
        # print(f"\n[Broadcast] {msg.payload.decode()}")
        msg_type = json.loads(msg.payload.decode())["type"]
        data = json.loads(msg.payload.decode())
        if msg_type == "N_O":
            logging.info(f'接收到N_O消息')
            N_O = bytes.fromhex(data["N_O"])
            sigma_V = verifier.sign_delta_t(N_O, delta_t)
            message = {
                "type": 'T_request',
                "sigma_V": sigma_V.hex(),
                "delta_t": delta_t
            }
            client.publish(TOPIC_SERVER, json.dumps(message))  # 向服务器发送连接消息

        if msg_type == "T_response":
            logging.info(f'接收到T_response消息')
            encrypted_T = data["encrypted_T"]
            # 解密T
            decrypted_T = verifier.decrypt_token(encrypted_T)
            logging.info(f'解密后的T: {decrypted_T}')
            I_list = data['ids']
            # 开始证明过程
            if decrypted_T:
                logging.info(f'开始证明过程...')
                N = os.urandom(32)
                ids = []
                message = {
                    "type": 'Ch',
                    "N": N.hex(),
                    "T": decrypted_T,
                    "ids": ids
                }
                client.publish(TOPIC_SERVER, json.dumps(message))

        if msg_type == "Ch":
            logging.info(f'接收到Ch消息')

        if msg_type == "res":
            logging.info(f'接收到res消息')
            tau = data['a_i']
            ids = data['ids']
            h_1 = data['h_1']
            D = data['D']
            apk = data['apk']
            S_t = list(set(I_list) - set(ids))
            if S_t:
                logging.info(f'未进行承诺的签名者ID（可能已经掉线）: {S_t}')
            M = BFValue
            if h_1[0] in H:
                for i in range(len(D)):
                    D[i] = tuple(D[i])
                logging.info(f'D: {D}')
                is_valid = verify_signature(tau, R_A, D , apk, M)
                logging.info(f"聚合签名验证结果: {is_valid}")
                for d in D:
                    S_attack.append(d[0])
                if S_attack:
                    logging.info(f'受攻击的设备id: {S_attack}')
                else:
                    logging.info(f'所有设备验证完成，均良好')
            else:
                logging.info(f'聚合器可能被攻击，协议终止')
                return
            end_time = time.time()
            logging.info(f'认证过程总耗时为：{end_time - start_time}秒')

    elif msg.topic == TOPIC_ALL:
        msg_type = json.loads(msg.payload.decode())["type"]
        if msg_type == "R_A":
            data = json.loads(msg.payload.decode())
            R_A = data['R_A']
    else:
        sender_ip = msg.topic.split('/')[-1]
        print(f"\n[BroadCast] From {sender_ip}: {msg.payload.decode()}")
        msg_type = msg.payload.decode().split(":")[0]
        if msg_type == "R_A":
            R_A = int(msg.payload.decode().split(":")[1])
    print("Enter message (IP:msg for private): ", end="")


# mqtt_client.py - 仅修改send_message()函数
def send_message(client):
    while True:
        text = input("Enter message in format 'IP:message' (e.g. 192.168.1.100:Hello): ")
        if ':' not in text:
            print("Error: Must specify target IP. Format: 'IP:message'")
            continue

        target_ip, message = text.split(':', 1)
        if target_ip == BROKER_IP:  # 发给服务器A
            client.publish(TOPIC_SERVER, f"{CLIENT_IP}:{message}")
        else:  # 发给其他客户端
            client.publish(f"rpi/client/{target_ip}", f"{CLIENT_IP}:{message}")




client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER_IP, 1883, 60)

# 启动发送线程
threading.Thread(target=send_message, args=(client,), daemon=True).start()

client.loop_forever()