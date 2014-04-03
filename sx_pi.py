#!/usr/bin/env python2
#encoding=utf-8
#该脚本请配合定时任务使用 建议的定时任务配置 见sx.conf
import sys,tprouter,sxbase

def main():
    '''
    这里配置信息
    '''
    g_u='' #闪讯帐号
    g_p='' #闪讯密码
    g_router_acc='admin' #路由的登陆用户名和密码
    g_router_pw='admin'
    g_router_ip='192.168.1.1' #路由ip
    gRouter=tprouter.TPRouter() #路由拨号类
    g_router_url='''/userRpm/PPPoECfgRpm.htm?
wantype=2&VnetPap=201&linktype=1&waittime=&Connect=%%C1%%AC+%%BD%%D3
&acc=%s&psw=%s'''.replace('\n','') #路由的拨号字串
    g_log_prefix='d:/tmp/'  #日志前缀


    '''
    配置结束
    '''

    
    log=sxbase.SxLog(g_log_prefix)
    arg=sys.argv
    log.logtime()
    net=sxbase.NetUtil()
    gRouter.setLogin(g_router_ip,g_router_acc,g_router_pw)
    gRouter.setAcc(g_u,g_p)
    gRouter.setUrl(g_router_url)
    hb=sxbase.SxHeartBeat(g_u,g_p,g_log_prefix)
    enc=sxbase.SxAccEncoder(g_u)
    if not enc.check():
        print 'Account Error'
        return
    if (len(arg)>1):
        if arg[1]=='i':
            ip=net.getIP()
            if ip:
                print(ip['ip'])
            else:
                print 'ip error'
        elif arg[1]=='d':
            gRouter.Dail()
        elif arg[1]=='h':
            hb.SendAllHB()
    else:
        ip=net.getIP()
        if not ip:
            gRouter.Dail()
            time.sleep(50)
            ip=net.getIP()
            if not ip:
                accs=log.getAccFromFile()
                for i in accs:
                    enc.update(i)
                    if not enc.check():
                        continue
                    gRouter.setAcc(i,g_p)
                    gRouter.Dail()
                    time.sleep(20)
                    ip=net.getIP()
                    if ip:
                        hb.setNewAcc(i,g_p)
                        break
            if ip:
                hb.SendAllHB()
            else:
                print 'NO acc right'
if __name__=='__main__':
    main()
