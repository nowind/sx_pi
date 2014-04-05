#!/usr/bin/env python2
#encoding=utf-8
import router,sxbase
'''
tp系列路由拨号实现
'''
class TPRouter(router.Router):
    def _genAuthHeader(self):
        baseauth=self._genAuth()
        return {'Authorization':baseauth,'Cookie':'Authorization=%s'%baseauth}
    def Dail(self,data=None):
        encoder=sxbase.SxAccEncoder(self._pppoe_acc,sxbase.SxAccEncoder.ENCODE_ROUTER)
        realacc=encoder.encode()
        realurl=self._url%(realacc,self._pppoe_pwd)
        self.get(realurl)
