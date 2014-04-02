#!/usr/bin/env python2
#encoding=utf-8
import router,sxbase

class TPRouter(router.Router):
    def Dail(self,data=None):
        encoder=sxbase.SxAccEncoder(self._pppoe_acc,sxbase.SxAccEncoder.ENCODE_ROUTER)
        realacc=encoder.encode()
        realurl=self._url%(realacc,self._pppoe_pwd)
        req=urllib2.Request(url=realurl,headers={'Authorization':
         'Basic '+auth})
        res=urllib2.urlopen(req,timeout=200)
        res.close()
