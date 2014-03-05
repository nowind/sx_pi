#!/usr/bin/env python2
#encoding=utf-8
#该脚本请配合定时任务使用 建议的定时任务配置 见sx.conf
#该版本为村python不依赖二进制编译库
#代码的讲解注释见之前的版本
import pyDes,pyAes,binascii
import time,hashlib,struct,sys,socket,urllib2,json,re
import os.path
des=pyDes.triple_des('1234ZHEJIANGXINLIWANGLEI',pyDes.CBC,'12345678')
aes=pyAes.new('xlzjhrprotocol3x',1)
server='pppoeh.114school.cn'
g_u=''
g_p=''
g_pathprefix='/tmp/' #新增，在win环境下情自行修改
g_router_acc='admin'
g_router_pw='admin'
g_router_url='''http://192.168.1.1/userRpm/PPPoECfgRpm.htm?
wantype=2&VnetPap=201&linktype=1&waittime=&Connect=%%C1%%AC+%%BD%%D3
&acc=%s&psw=%s'''.replace('\n','')
def getPIN():
    global g_u
    us=g_u
    RAD="zjxinlisx01"
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
    return PIN
def Dail():
    global g_router_url,g_router_acc,g_router_pw,g_p,g_u
    if not re.search('\d{10,15}@dzkd.xy',g_u,re.IGNORECASE):
        return
    PIN='%0D%0A'+urllib2.quote(getPIN())
    auth='%s:%s'%(g_router_acc,g_router_pw)
    auth=auth.encode("base64")[0:-1]
    realurl=g_router_url%(PIN,g_p)
    req=urllib2.Request(url=realurl,headers={'Authorization':
         'Basic '+auth})
    res=urllib2.urlopen(req,timeout=200)
    res.close()
def HR10():
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ramdata='type=6;%did=%s&pwd=%s;ver=%s;time=%d'
    l=(8-len(ramdata)%8)%8
    ramdata=ramdata+l*chr(l)
    data='%s%s%s%s'%('HR10',#header
                     '\x05\x00\x00\x00',#
                     '\x28',#size
                     des.encrypt(ramdata))
    sock.sendto( data,(server, 444))
    sock.close()
def HR20():
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ramdata='7;%s;%s;%s;%s;%d;%s;%d'
    l=(16-len(ramdata)%16)%16
    ramdata=ramdata+l*chr(l)
    data='%s%s%s%s'%('HR20',
                     '\x05\x00\x00\x00',
                     '\x20',
                     aes.encrypt(ramdata))
    sock.sendto(data,(server, 445))
    sock.close()
def HR30send1():
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ramdata='8;%08x;%s;%s;%s;%d;%d'
    l=(16-len(ramdata)%16)%16
    ramdata=ramdata+l*chr(l)
    data='%s%s%s%s'%('HR30',
                     '\x02\x05\x00\x00\x00',
                     '\x20',
                     aes.encrypt(ramdata))
    sock.sendto(data,(server, 446))
    sock.close()
def getIP():
    try:
        res=urllib2.urlopen('http://whois.pconline.com.cn/ipJson.jsp',timeout=2)
    except:
        return None
    if res.getcode()!=200:
        return None
    re=res.read().decode('gbk').encode('utf8')
    res.close()
    re=re[re.rfind('{'):re.find('}')+1]
    return json.loads(re)
def HR30send2():
    global g_u,g_p,g_pathprefix
    us=g_u
    pw=g_p
    mac='08:00:27:00:24:FD'
    ip=getIP()
    if not ip:
        return ''
    else:
        ip=ip['ip']
    if not os.path.isfile(g_pathprefix+"sxkey"):
    	key='123456'
    else:
    	with open(g_pathprefix+"sxkey",'r+') as file:
    		key=file.read()
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ramdata='TYPE=HEARTBEAT&USER_NAME=%s&PASSWORD=%s&IP=%s&MAC=%s&VERSION_NUMBER=1.0.1&PIN=MAC_TEST&DRIVER=1&KEY=%s'%(
        us,pw,ip,mac,key)
    #ramdata=ramdata
    l=(16-len(ramdata)%16)%16
    ramdata=ramdata+l*chr(l)
    data='%s%s%s%s'%('HR30',
                     '\x02\x05\x00\x00\x00',
                     chr(len(ramdata)),
                     aes.encrypt(ramdata.encode('ascii')))
    sock.settimeout(2.0)
    sock.sendto(data,(server, 443))
    buff=sock.recvfrom(200)
    mykey=aes.decrypt(buff[0][9:])
    sock.close()
    with open(g_pathprefix+'sxkey.txt','w+') as f:
        keypos=mykey.rfind('=')
        if keypos!=-1:
            f.write(mykey[keypos+1:keypos+7])
    return mykey
def sendHeart():
    global g_pathprefix
    HR10()
    HR20()
    HR30send1()
    HR30send2()
    time.sleep(1)
    with open(g_pathprefix+'sxlog.txt','w+') as file:
        file.write(HR30send2())
def main():
    global g_pathprefix
    arg=sys.argv
    with open(g_pathprefix+'sxlast.txt','w+') as file:
        file.write(time.strftime("%x %X"))
    if (len(arg)>1):
        if arg[1]=='i':
            ip=getIP()
            if ip:
                print(ip['ip'])
            else:
                print 'ip error'
        elif arg[1]=='d':
            Dail()
        elif arg[1]=='h':
            sendHeart()
    else:
        ip=getIP()
        if not ip:
            Dail()
            time.sleep(50)
            ip=getIP()
            if not ip:
                if os.path.isfile(g_pathprefix+'sxacc'): #新增，方便多账号，该文件可以用其他方式写入
                    global g_u
                    with open(g_pathprefix+'sxacc','r+') as f:
                        while not ip:
                            acc=f.readline().replace('\n','')
                            g_u=acc
                            Dail()
                            time.sleep(50)
                            ip=getIP()
            if ip:
                sendHeart()
            else:
                print 'NO acc right'
if __name__=='__main__':
    main()

