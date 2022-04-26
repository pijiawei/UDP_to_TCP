import socket
import sys
import rsa
import base64
import datetime
import colorama
from colorama import init

init(autoreset=True)
from os.path import basename
from Crypto.Cipher import AES
from threading import Thread, Event
from time import sleep

# coding=gbk
'''
项目说明：
    通过UDP实现安全可靠的TCP通信
    主要是在UDP通信的基础上，实现TCP的三次握手建立连接，四次挥手断开连接的功能
    在此基础上，通过加密解密手段来实现对接受发送的数据进行处理，这样能够使安全性更进一步。
    本次代码用于本机回环测试
    本项目客户端与服务端均需要同时发送接收，使用多线程
'''
'''
包结构说明（按先后顺序）：
    seq ：序列号
    ack_seq : 确认序列号
    ACK : 确认ACK，只有在ACK = 1 时，确认号字段才有效
    PSH : PSH = 1，立即创建报文并发送，不需要积累足够多的数据便发送
    RST : RST = 1, 表示连接中出现严重差错，必须释放连接，再重新建立运输连接
    SYN : SYN = 1,ACK = 0代表这是一个连接请求报文段，SYN = 1,ACK = 1 代表对方统一建立连接。
    FIN : 用来释放连接，FIN = 1 代表此报文段的发送方数据已经发送完毕，并要求释放运输连接
    winsize : 窗口，指发送方预期的接收窗口
    data: 发送的数据信息
'''

'''
补充说明：
    因为python 版本不同，对于Crypto库，当出现不可使用的情况时，可替换为Cryptodome
'''

# ----------------------- 参数说明 ----------------------------------------
BUFFER_SIZE = 1 << 15
aes_pw = '9876543210123456'  # aes密钥

# 发送的测试数据的地址
# filepath = r'C:\Users\20614\Desktop'
filepath = input('Please input the file pakege name(传输文件所在的文件目录，并‘\’改写为‘\\\‘）:')
filename = input("Please enter the file name (suffix included) ：")
filepath = filepath + "\\" + filename
# 获得发送的测试文件的文件名
filename = [f'{basename(filepath)}'.encode()]

# 改写为可输入
ip = str(input('请输入接收方的IP地址:'))
addr = (ip, 7777)

positions = []

# 用于通信
# 创建UDP Socket
rsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.bind(addr),将套接字绑定到地址, 在AF_INET下,以元组（host,port）的形式表示地址
rsock.bind(('', 7778))
# 初始化接受到的数据报文
global r_data  # 接受到的包需要在接受线程和发送线程里使用，因此定义为全局变量
r_data = [0] * 8
r_data.append(b'0')


# ---------------------- 包结构生成部分 ------------------------------------
def generatepack(seq, ack_seq, ACK, PSH, RST, SYN, FIN, winsize, DATA):
    pack = bytes(
        str(seq) + '.' + str(ack_seq) + '.' + str(ACK) + '.' + str(PSH) + '.' + str(RST) + '.' + str(SYN) + '.' + str(
            FIN) + '.' + str(winsize) + '.', encoding='utf-8') + DATA
    return pack


# -------------------- 三次握手 -------------------------------------
def handshake(SEQ, ACK_SEQ, flag, s_sock):
    # 第一次握手
    time_before_sent = datetime.datetime.now()
    while True:
        # 发送请求建立连接报文
        s_pack = generatepack(SEQ, 0, 0, 0, 0, 1, 0, 1, b'0')
        s_sock.sendto(s_pack, addr)
        # 在规定时间内不断向B发送连接建立请求信号，并在不断获取B发送的连接建立请求同意信号
        time_before_get = datetime.datetime.now()
        while True:
            if (r_data[1] == SEQ + 1 and r_data[2] == 1 and r_data[5] == 1):
                str_key = r_data[8]  # 取RSA公钥
                key = rsa.PublicKey.load_pkcs1(str_key)
                SEQ += 1
                ACK_SEQ = r_data[0] + 1
                flag = 1
                break
            else:
                time_now_get = datetime.datetime.now()
                if ((time_now_get - time_before_get).seconds >= 2):
                    break
        if flag == 1:
            break
        else:
            time_now_sent = datetime.datetime.now()
            if ((time_now_sent - time_before_sent).seconds >= 6):
                break
    if flag == 0:
        print('Second Handshake:      \033[1;31mFail\033[0m')
        sys.exit(0)
    else:
        print('Second Handshake:      \033[1;32mSucceed\033[0m')
        flag = 0

    # 将aes密钥用RSA公钥作加密
    en_aes_pw = rsa.encrypt(aes_pw.encode('utf-8'), key)

    # 第三次握手
    # 在第三次握手的同时，将加密之后的ase密钥发送给B
    s_pack = generatepack(SEQ, ACK_SEQ, 1, 0, 0, 0, 0, 1, en_aes_pw)
    s_sock.sendto(s_pack, addr)
    SEQ += 1
    sleep(0.1)

    return SEQ, ACK_SEQ, flag


# -------------------- 四次挥手 -------------------------
def wave(SEQ, ACK_SEQ, flag, s_sock):
    time_before_sent = datetime.datetime.now()
    while True:
        s_pack = generatepack(SEQ, ACK_SEQ, 0, 0, 0, 0, 1, 1, b'0')
        s_sock.sendto(s_pack, addr)
        time_before_get = datetime.datetime.now()
        while True:
            if (r_data[1] == SEQ + 1 and r_data[2] == 1):
                SEQ += 1
                ACK_SEQ = r_data[0] + 1
                flag = 1
                break
            else:
                time_now_get = datetime.datetime.now()
                if ((time_now_get - time_before_get).seconds >= 2):
                    break

        if flag == 1:
            break
        else:
            time_now_sent = datetime.datetime.now()
            if ((time_now_sent - time_before_sent).seconds >= 6):
                print('First Wavehand:        \033[1;31mTime Out\033[0m')
                print('Received Message: ', r_data)
                break

    if flag == 0:
        print('First Wavehand:        \033[1;31mFail\033[0m')
        sys.exit(0)
    else:
        print('First Wavehand:        \033[1;32mSucceed\033[0m')
        flag = 0

    # 一次挥手和四次挥手之间做延迟，确保四次挥手接收的是B三次挥手的确认信号
    sleep(2)

    # 第四次挥手
    time_before_sent = datetime.datetime.now()
    while True:
        if (r_data[6] == 1):
            ACK_SEQ = r_data[0] + 1
            s_pack = generatepack(SEQ, ACK_SEQ, 1, 0, 0, 0, 0, 1, b'0')
            s_sock.sendto(s_pack, addr)
            flag = 1
            break
        else:
            time_now_sent = datetime.datetime.now()
            if ((time_now_sent - time_before_sent).seconds >= 2):
                print('Fourth Wavehand:       \033[1;31mFail\033[0m.')
                print('Received Message: ', r_data)
                break

    if flag == 0:
        print('Fourth Wavehand:       \033[1;31mFail\033[0m')
        sys.exit(0)
    else:
        print('Fourth Wavehand:       \033[1;32mSucceed\033[0m')

    return SEQ, ACK_SEQ, flag


# ---------------------- 线程之一：接受包部分 -------------------------------------
def pack_receive():
    global r_data
    while True:
        # 接受UDP套接字的数据与地址
        r_temp, r_addr = rsock.recvfrom(1024)
        r_data = r_temp.split(b'.', 8)
        # r_temp = r_temp.split(b'.',8)
        # 用于将添加的UDP报文头部转换为int数据类型
        if len(r_data) == 9:
            for i in range(8):
                r_data[i] = int(r_data[i].decode())


# ---------------------- 线程之一：发送数据部分 -----------------------------------
def pack_sent(filepath):
    # 初始化序列号与确认序列号
    SEQ = 0
    ACK_SEQ = 0
    # 建立UDP套接字
    s_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFFER_SIZE)
    # 确认标志
    flag = 0

    '''
    在传输数据之前，需要经历三次握手
    '''
    SEQ, ACK_SEQ, flag = handshake(SEQ, ACK_SEQ, flag, s_sock)

    # 数据加密
    with open(filepath, 'rb') as fp:
        thing_in_path = fp.read()
    addnum = 16 - len(thing_in_path) % 16
    thing_in_path = thing_in_path + addnum * b'\0'
    model = AES.MODE_ECB  # 定义模式
    aes = AES.new(aes_pw.encode('utf-8'), model)  # 创建一个aes对象
    thing_in_path = aes.encrypt(thing_in_path)  # 通过aes加密发送的文件内容
    for start in range(len(thing_in_path) // BUFFER_SIZE + 1):
        positions.append(start * BUFFER_SIZE)

    # 发送数据
    for pos in positions:
        for s_cnt in range(5):
            sleep((0.1))
            s_pack = generatepack(SEQ, ACK_SEQ, 0, 0, 0, 0, 0, 1, thing_in_path[pos:pos + BUFFER_SIZE])
            s_sock.sendto(s_pack, addr)
            for r_cnt in range(6):
                sleep(0.5)
                if r_cnt == 5:
                    break
                elif (r_data[2] == 1 and r_data[1] == SEQ + len(thing_in_path[pos:pos + BUFFER_SIZE])):
                    SEQ = SEQ + len(thing_in_path[pos:pos + BUFFER_SIZE])
                    ACK_SEQ = r_data[0] + 1
                    flag = 1
                    break
            if flag == 1:
                break
        if flag == 0:
            print('Send Data:             \033[1;31mFail\033[0m')
            sys.exit(0)
        else:
            flag = 0
            print('Send Data:             \033[1;32mSucceed\033[0m')

            # 发送文件名
    for s_cnt in range(21):
        s_pack = generatepack(SEQ, ACK_SEQ, 0, 0, 0, 0, 0, 1, b'over_' + filename[0])
        s_sock.sendto(s_pack, addr)
        for r_cnt in range(21):
            sleep(0.5)
            if r_cnt == 20:
                break
            elif (r_data[2] == 1 and r_data[1] == SEQ + len(filename[0])) + 5:
                SEQ = SEQ + len(filename[0]) + 5
                ACK_SEQ = r_data[0] + 1
                flag = 1
                break

        if flag == 1:
            break

    if flag == 0:
        print('Send Filename:         \033[1;31mFail\033[0m')
        sys.exit(0)
    else:
        print('Send Filename:         \033[1;32mSucceed\033[0m')
        flag = 0

    '''
    在数据发送完毕之后，进行四次挥手来断开连接
    '''
    SEQ, ACK_SEQ, flag = wave(SEQ, ACK_SEQ, flag, s_sock)


# --------------- 主函数部分 ---------------

threading_sent = Thread(target=pack_sent, args=(filepath,))
threading_sent.start()
threading_rec = Thread(target=pack_receive)
threading_rec.start()
threading_rec.join()
threading_sent.join()