#!/usr/bin/env python2
#encoding=utf-8
import time,hashlib,struct,urllib2,time,sys,json,socket,re
import os.path
import pyDes,pyAes,binascii
class SxAccEncoder(object):
    '''
    负责账号的加密
'''
    ENCODE_NONE=1
    ENCODE_ROUTER=2
    ENCODE_OTHER=3
    def __init__(self,acc='',e=ENCODE_NONE):
        self._acc=acc
        self._e=e
    def check(self):
        if not re.search('\d{10,15}@dzkd.xy',self._acc,re.IGNORECASE):
            return False
        return True
    def update(self,acc):
        self._acc=acc
    def encode(self):
        RAD="zjxinlisx01"
        us=self._acc
        timeHash=[0,0,0,0]
        timedivbyfive=int(time.time())//5
        for i in range(0,4):
            for j in range(0,8):
                timeHash[i]=timeHash[i]+(((timedivbyfive>>(i+4*j))&1)<<(7-j))
        m=hashlib.md5()
        bm=struct.pack('>I',timedivbyfive)+(us.split('@')[0]+RAD).encode('ascii')
        m.update(bm)
        pk=m.hexdigest()[0:2]
        PIN27=[0,0,0,0,0,0]
        PIN2=''
        PIN27[0]=((timeHash[0]>>2)&0x3F)
        PIN27[1]=((timeHash[0]&0x03)<<4&0xff)|((timeHash[1]>>4)&0x0F)
        PIN27[2]=((timeHash[1]&0x0F)<<2&0xff)|((timeHash[2]>>6)&0x03)
        PIN27[3]=timeHash[2]&0x3F
        PIN27[4]=((timeHash[3]>>2)&0x3F)
        PIN27[5]=((timeHash[3]&0x03)<<4&0xff)
        for i in range(6):
            PIN27[i]={True:(PIN27[i]+0x20)&0xff,False:(PIN27[i]+0x21)&0xff}[((PIN27[i]+0x20)&0xff)<0x40]
        for i in range(6):
            PIN2=PIN2+chr(PIN27[i])
        PIN=PIN2+pk+us #'\x0D\x0A'+
        if self._e==self.ENCODE_ROUTER:
            PIN='%0D%0A'+PIN
        elif self._e==self.ENCODE_OTHER:
            PIN='\x0D\x0A'+PIN
        return PIN
class NetUtil(object):
    '''
    负责网络连通性检测
'''
    def getIP(self):
        try:
            res=urllib2.urlopen('http://whois.pconline.com.cn/ipJson.jsp',timeout=2000)
        except:
            return None
        if res.getcode()!=200:
            return None
        re=res.read().decode('gbk').encode('utf8')
        res.close()
        re=re[re.rfind('{'):re.find('}')+1]
        return json.loads(re)
class SxLog(object):
    '''
    负责日志，key等信息
'''
    def __init__(self,prefix='/tmp/'):
        self._prefix=prefix
    def logtime(self):
        with open(self._prefix+'sxlast','w+') as file:
            file.write(time.strftime("%x %X"))
    def logHB(self,s):
        with open(self._prefix+'sxlog','w+') as file: #记录数据
            file.write(s)
    def trygetkey(self):
        if not os.path.isfile(self._prefix+"sxkey"): #读取key 没有则使用默认
            key='123456'
        else:
            with open(self._prefix+"sxkey",'r+') as file:
                key=file.read()
        return key
    def writekey(self,mykey):
        with open(self._prefix+'sxkey','w+') as f:
            keypos=mykey.rfind('=')
            if keypos!=-1:
                f.write(mykey[keypos+1:keypos+7])
        return mykey
    def getAccFromFile(self):
        acc=[]
        if os.path.isfile(self._prefix+'sxacc'): #新增，方便多账号，该文件可以用其他方式写入
            with open(self._prefix+'sxacc','r+') as f:
                acc.append(f.readline().replace('\n',''))
        return acc
class SxHeartBeat(object):
    '''
    主心跳
'''
    def __init__(self,acc,pwd,mac=None,pre='/tmp/'):
        self._server='pppoeh.114school.cn'
        self._acc=acc
        self._pwd=pwd
        self._prefix=pre
        self._aes=pyAes.new('xlzjhrprotocol3x',1)
        self._des=pyDes.triple_des('1234ZHEJIANGXINLIWANGLEI',pyDes.CBC,'12345678')
        if mac:
            self._mac=mac
        else:
            self._mac='08:00:27:00:24:FD'
    def setNewAcc(self,acc,pwd):
        self._acc=acc
        self._pwd=pwd
    def _padData(self,s,length=16):
        l=(length-len(s)%length)%length #填充
        return s+l*chr(l)
    def HR10(self): #心跳包
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ramdata=self._padData('type=6;%did=%s&pwd=%s;ver=%s;time=%d',8) #原始数据
        data='%s%s%s%s'%('HR10',#header
                         '\x05\x00\x00\x00',#
                         '\x28',#size
                         self._des.encrypt(ramdata)) #加密
        sock.sendto( data,(self._server, 444))
        sock.close()
    def HR20(self):
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ramdata=self._padData('7;%s;%s;%s;%s;%d;%s;%d')
        data='%s%s%s%s'%('HR20',
                         '\x05\x00\x00\x00',
                         '\x20',
                         self._aes.encrypt(ramdata))
        sock.sendto(data,(self._server, 445))
        sock.close()
    def HR30send1(self):
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ramdata=self._padData('8;%08x;%s;%s;%s;%d;%d')
        data='%s%s%s%s'%('HR30',
                         '\x02\x05\x00\x00\x00',
                         '\x20',
                         self._aes.encrypt(ramdata))
        sock.sendto(data,(self._server, 446))
        sock.close()
    def HR30send2(self):
        net=NetUtil()
        ip=net.getIP()
        if not ip:
            return ''
        else:
            ip=ip['ip']
        log=SxLog(self._prefix)
        key=log.trygetkey()
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ramdata=self._padData('TYPE=HEARTBEAT&USER_NAME=%s&PASSWORD=%s&IP=%s&MAC=%s&VERSION_NUMBER=1.0.1&PIN=MAC_TEST&DRIVER=1&KEY=%s'%(
            self._acc,self._pwd,ip,self._mac,key))
        #这里使用mac系统的心跳包
        data='%s%s%s%s'%('HR30',
                         '\x02\x05\x00\x00\x00',
                         chr(len(ramdata)),
                         self._aes.encrypt(ramdata.encode('ascii')))
        sock.settimeout(2.0)
        sock.sendto(data,(self._server, 443))
        buff=sock.recvfrom(200)
        mykey=self._aes.decrypt(buff[0][9:])
        sock.close()
        log.writekey(mykey)
    def SendAllHB(self):
        self.HR10()
        self.HR20()
        self.HR30send1()
        self.HR30send2()
        time.sleep(1)
        self.HR30send2()
