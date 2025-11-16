# mqtt_client.py - 运行在B/C/D上
import paho.mqtt.client as mqtt
import threading
from Sign import *
import logging
from TokenIssue import *
import json


logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')

node_signer = Signer(2)

def insert_bloom_filter(configs):
    """创建布隆过滤器"""
    bf = BloomFilter(capacity=100, error_rate=0.001)
    for config in configs:
        bf.add(config)
    # 返回bf
    return bf

N = b''  #存储验证者发送的随机数
H = ["configure1", "configure2", "configure3"]
h = ["configure2"]
BFValue = insert_bloom_filter(H).bitarray
c_l = 2
v_l = 0

# 配置（每个客户端需要修改）
BROKER_IP = "192.168.3.128"  # A的IP
CLIENT_IP = "192.168.3.142"   # 当前设备的IP
TOPIC_ALL = "rpi/all"
TOPIC_SERVER = "rpi/server/2"
TOPIC_OWNER = "rpi/server/owner"
TOPIC_CLIENT = f"rpi/client/{CLIENT_IP}"  # 当前客户端的专属频道

def on_connect(client, userdata, flags, rc):
    print("Connected to Server!")
    client.subscribe(TOPIC_ALL)      # 订阅广播
    client.subscribe(TOPIC_CLIENT)   # 订阅自己的专属频道
    message = {
        "type": "PK_P",
        "PK_P": node_signer.pk,
    }
    client.publish(TOPIC_SERVER, json.dumps(message))
    client.publish(TOPIC_OWNER, json.dumps(message))

def on_message(client, userdata, msg):
    global N
    if msg.topic == TOPIC_CLIENT:
        msg_type = json.loads(msg.payload.decode())["type"]
        data = json.loads(msg.payload.decode())
        if msg_type == "Ch":
            logging.info(f'接收到Ch消息')
            R_i = node_signer.R
            message = {
                "type": "R_i",
                "R_i": R_i,
                "id": node_signer.id
            }
            N = bytes.fromhex(data['N'])
            client.publish(TOPIC_OWNER, json.dumps(message))
            client.publish(TOPIC_SERVER, json.dumps(message))

    elif msg.topic == TOPIC_ALL:
        msg_type = json.loads(msg.payload.decode())["type"]
        if msg_type == "R_A":
            data = json.loads(msg.payload.decode())
            R_A = data['R_A']
            bfValue = insert_bloom_filter(h)
            # if h in H:
            #     bfValue = BFValue
            M = BFValue
            m = str(bfValue).encode() + N + str(v_l).encode() + str(c_l).encode()
            tau = node_signer.sign(M, R_A)
            D = generate_D_1(node_signer, M, M)
            logging.info(f'聚合签名τ = {tau}')
            logging.info(f'D = {D}')
            message = {
                "type": "a_i",
                "tau": tau,
                "D": D
            }
            logging.info(f'已经进行签名')
            client.publish(TOPIC_SERVER, json.dumps(message))

    else:
        sender_ip = msg.topic.split('/')[-1]
        print(f"\n[BroadCast] From {sender_ip}: {msg.payload.decode()}")
        # msg_type = msg.payload.decode().split(":")[0]
        # if msg_type == "R_A":
        #     R_A = msg.payload.decode().split(":")[1]
        #     bfValue = insert_bloom_filter(h)
        #     if h in H:
        #         bfValue = BFValue
        #     M = BFValue
        #
        #
        #     m = str(bfValue).encode() + N + str(v_l).encode() + str(c_l).encode()
        #     tau = node_signer.sign(M, R_A)
        #     D = generate_D_1(node_signer, M, M)
        #     logging.info(f'聚合签名τ = {tau}')
        #     logging.info(f'D = {D}')
        #     message = {
        #         "type": "a_i",
        #         "tau": tau,
        #         "D": D
        #     }
        #     client.publish(TOPIC_SERVER, json.dumps(message))

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

# def verify():
#     # 发送R_i
#     R_i = node_signer.R
#     client.publish(TOPIC_SERVER, f"R_i:{node_signer.id}:{R_i}")



client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER_IP, 1883, 60)

# 启动发送线程
threading.Thread(target=send_message, args=(client,), daemon=True).start()

client.loop_forever()
