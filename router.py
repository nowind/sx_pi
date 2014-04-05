#!/usr/bin/env python2
#encoding=utf-8
import urllib2,copy
from abc import ABCMeta,abstractmethod

class Router(object):
    '''
    路由的抽象类，实现他的Dail函数
'''
    __metaclass__ = ABCMeta
    def __init__(self):
        self._acc='admin'
        self._pwd='admin'
        self._ip='192.168.1.1'
        self._url='/'
        self._pppoe_acc=''
        self._pppoe_pwd=''
    def setLogin(self,ip,acc,pwd):
        self._acc=acc
        self._pwd=pwd
        self._ip=ip
        return self
    def setAcc(self,user,pwd):
        self._pppoe_acc=user
        self._pppoe_pwd=pwd
        return self
    def get(self,url,headers={}):
        reqheader=copy.deepcopy(headers)
        reqheader.update(self._genAuthHeader())
        req=urllib2.Request(url='http://'+self._ip+url,headers=reqheader)
        res=urllib2.urlopen(req,timeout=200)
        r=res.read()
        res.close()
        return r
    def _genAuth(self):
        auth='%s:%s'%(self._acc,self._pwd)
        return 'Basic '+auth.encode("base64")[0:-1]
    def _genAuthHeader(self):
        baseauth=self._genAuth()
        return {'Authorization':baseauth}
    def _getCookie(self):
        try:
            header=self._genAuthHeader()
            req=urllib2.Request('http://'+self._ip,headers=header)
            res=urllib2.urlopen(req,timeout=200)
            c=res.info().getheader('Set-Cookie')
            res.close()
            return c
        except:
            return ''
    def setUrl(self,u):
        self._url=u
        return self
    @abstractmethod
    def Dail(self,data=None):
        pass
