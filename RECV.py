import socket
import sys
import datetime
import os
import base64
import rsa
import colorama
from colorama import init,Fore,Back,Style
init(autoreset=True)
from os.path import basename
from threading import Thread, Event
from time import sleep
from Crypto.Cipher import AES
#coding=gbk
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


#--------------------------- 参数说明 -------------------------------

path = r'D:\receive'
if os.path.exists(path):
    pass
else:
    os.mkdir(path)

# 接收文件存储路径
sto = r'D:\receive'
BUFFER_SIZE = 1<<22

# IP地址与端口
#addr = ('127.0.0.1',7778)
ip = str(input('请输入发送端的IP地址: '))
addr = (ip,7778)

# 用于与另一部电脑进行通信的IP地址与端口号
#addr = ('10.195.188.155',7778)

# 创建UDP Socket
rsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rsock.bind(('',7777))

# 接收数据初始化
data = set()
r_data = [0]*8
r_data.append([b'0'])
r_temp = b'0'


#---------------------- 包结构生成部分 ------------------------------------
def generatepack(seq,ack_seq,ACK,PSH,RST,SYN,FIN,winsize,DATA):
    pack = bytes(str(seq)+'.'+str(ack_seq)+'.'+str(ACK)+'.'+str(PSH)+'.'+str(RST)+'.'+str(SYN)+'.'+str(FIN)+'.'+str(winsize)+'.',encoding='utf-8')+DATA
    return pack

#---------------------- 三次握手部分 --------------------------------------
def shakehand(SEQ,ACK_SEQ,flag,s_sock,key_str,pvtkey):
    # 第一次握手处理
    while True:
        if (r_data[5] == 1):
            ACK_SEQ = r_data[0] + 1
            # 在发送建立连接同意报文的同时，发送自己的RSA公钥
            s_pack = generatepack(SEQ,ACK_SEQ,1,0,0,1,0,1,key_str)
            s_sock.sendto(s_pack, addr)
            break
    print('First Handshake:            \033[1;32mSucceed\033[0m')

    # 第二次握手
    # 在此时，不断接收A在第三次握手阶段发送的确认报文，即包含加密之后的aes密钥的报文
    time_before = datetime.datetime.now()
    while True:
        if (r_data[2] == 1):
            # 取出A在第三次握手阶段发送的aes密钥
            en_aes_pw = r_data[8]
            # 使用rsa私钥解密aes密钥
            aes_pw = rsa.decrypt(en_aes_pw, pvtkey).decode('utf-8')
            print('Decryption Key:', aes_pw)
            SEQ += 1
            ACK_SEQ = r_data[0] + 1
            flag = 1
            break
        else:
            time_now = datetime.datetime.now()
            if ((time_now - time_before).seconds > 2):
                break
    if flag == 0:
        print('Third Handshake:            \033[1;31mFail\033[0m')
        sys.exit(0)
    else:
        print('Third Handshake:            \033[1;32mSucceed\033[0m. Communication Links established.')
        flag = 0
    return SEQ,ACK_SEQ,flag,aes_pw

#---------------------- 四次挥手部分 --------------------------------------
def wave(SEQ,ACK_SEQ,flag,s_sock):
    # 第二次挥手
    time_before = datetime.datetime.now()
    while True:
        if (r_data[6] == 1):
            ACK_SEQ = r_data[0] + 1
            s_pack = generatepack(SEQ,ACK_SEQ,1,0,0,0,0,1,b'01')
            s_sock.sendto(s_pack, addr)
            break
        else:
            time_now = datetime.datetime.now()
            if ((time_now - time_before).seconds >= 2):
                print('Second Wavehand:            \033[1;31mFail\033[0m')
                sys.exit(0)
    print('Second Wavehand:            \033[1;32mSucceed\033[0m')

    # 二次挥手与三次挥手之间做延迟，保证一次挥手的确认信号能被A接收
    sleep(2)

    # 第三次挥手
    time_before_sent = datetime.datetime.now()
    while True:
        s_pack = generatepack(SEQ,ACK_SEQ,0,0,0,0,1,1,b'11')
        s_sock.sendto(s_pack, addr)
        time_before_get = datetime.datetime.now()
        while True:
            if ( r_data[1] == SEQ + 1 and r_data[2] == 1 ):
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
            if ((time_now_sent - time_before_sent).seconds >= 10):
                print('Third Wavehand: Time Out')
                print('Received Message: ', r_data)
                break
    if flag == 0:
        print('Third Wavehand:             \033[1;31mFail\033[0m')
        sys.exit(0)
    else:
        print('Third Wavehand:             \033[1;32mSucceed\033[0m')
        flag = 0

#---------------------- 数据解密与解密后数据存储部分 -------------------------------------
def decrypt_store(data,file_name,aes_pw):
    # 将加密数据按照序列号做排列，保证文件内容不是乱码
    data = sorted(data, key=lambda a: int(a[0]))
    with open (rf'{sto}\{file_name}','wb') as f:
        data_code = b''
        for a in data:
            data_code +=a[1]
        # 定义模式为ECB
        model = AES.MODE_ECB
        aes = AES.new(aes_pw.encode('utf-8'), model)
        data_code = aes.decrypt(data_code)
        data_code = data_code.rstrip(b'\0')
        f.write(data_code)
    print('%s%s%sDecrypted，Check in%s%s%s' % ("\033[1;34m " , file_name, "\033[0m" ,"\033[34m", sto,"\033[0m"))

#---------------------- 线程之一：握手，挥手与数据接收存储 ---------------------------------
def pack_sent():
    global r_data
    global data
    SEQ = 0
    ACK_SEQ = 0
    flag = 0

    # 建立一对rsa公钥和私钥，用于对aes秘钥的加密解密
    (key, pvtkey) = rsa.newkeys(512)
    key_str = key.save_pkcs1()

    # 建立UDP套接字
    s_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFFER_SIZE)

    '''
    首先通过三次握手与A（发送端）建立连接
    '''
    SEQ,ACK_SEQ,flag,aes_pw = shakehand(SEQ,ACK_SEQ,flag,s_sock,key_str,pvtkey)

    '''
    握手完毕，成功建立连接之后，开始做数据接收
    思路：
        在发送端发送数据时，首先是发送加密之后的数据，当文件内容发送完毕之后，就是发送文件名
        因此判断接收的DATA是否是文件名可判断当前文件是否接收完毕
        并做出错判断：
            当距离上一次正确接收文件内容之后，过了一定时间T之后还没有接受到文件内容或者文件名，
            代表接收出错，做报错退出处理
    '''
    time_get_now = datetime.datetime.now()
    while True:
        # 判断序列号是否为确认序列号,是文件名，是代表接收的数据没有出错,且代表接收结束
        if (r_data[0] == ACK_SEQ and r_data[8].startswith(b'over')):
            # 解码得到文件名
            filename = r_data[8][5:].decode()
            ACK_SEQ+= len(r_data[8])
            # 接收到数据之后，向A发送确认报文
            s_pack = generatepack(SEQ,ACK_SEQ,1,0,0,0,0,1,b'0')
            s_sock.sendto(s_pack, addr)
            time_get_now = datetime.datetime.now()
            break
        elif r_data[0] == ACK_SEQ:
            # 接收到数据之后，向A发送确认报文
            ACK_SEQ = ACK_SEQ + len(r_data[8])
            s_pack = generatepack(SEQ,ACK_SEQ,1,0,0,0,0,1,b'0')
            s_sock.sendto(s_pack, addr)
            # 将接收到的序列号与数据一一对应存入数组中，对序列号排序便可以回复原有的文件内容顺序
            # 从而避免了乱码
            data.add((r_data[0], r_data[8]))
            time_get_now = datetime.datetime.now()
        else :
            time_get_late = datetime.datetime.now()
            # 做接收数据出错判断与处理
            if ((time_get_late - time_get_now).seconds >= 5):
                print('数据接收出错，下面是当前接收到的报文信息：')
                print(r_data)
                exit(0)
    print('\033[1;34mMessage received\033[0m. Ready to disconnect.' )

    '''
    在数据传输完毕之后，进入四次挥手阶段断开发送端与接收端的连接
    '''
    wave(SEQ,ACK_SEQ,flag,s_sock)

    '''
    在挥手成功，断开连接之后
    代表整个传输成功完成
    进入接收数据解密与存储部分
    '''
    decrypt_store(data,filename,aes_pw)



#---------------------- 线程之二：数据接收 ---------------------------------
def pack_receive():
    global r_data
    global BUFFER_SIZE
    while True:
        # 接收UDP套接字的数据与地址
        r_temp, r_addr = rsock.recvfrom(BUFFER_SIZE)
        r_data = r_temp.split(b'.',8)
        if len(r_data) == 9:
            for i in range(8):
                r_data[i] = int(r_data[i].decode())

#---------------------- 主程序 -------------------------------------------
threading_sent = Thread(target=pack_sent)
threading_sent.start()
threading_rec = Thread(target = pack_receive)
threading_rec.start()
threading_rec.join()
threading_sent.join()