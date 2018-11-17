#!/usr/bin/python2
# -*- coding: utf8 -*-

import json
import urllib
import urllib2

class getRestJSON:
    def __init__(self , url = "" , params = "" ):
        self.url = url
        self.params = dict(params)
        self.jsres = []
    
    def setURL(self,url):
        self.url = url
    
    def addParam(self,param):
        self.params.update(param)
        
    def getData(self):
        params_enc = urllib.urlencode( self.params )
        try:
            req = urllib2.Request(self.url+"?"+params_enc, headers={ 'User-Agent': 'Mozilla/5.0' })
            self.webrsc = urllib2.urlopen(req)
            self.jsres = json.load(self.webrsc)
        except:
            raise IOError("Error while processing request:\n%s"%(self.url+"?"+params_enc))
    
    def getKey(self,keychar):
        out=self.jsres
        path=keychar.split("/")
        for key in path:
            if key.isdigit(): key=int(key)
            try:
                out = out[key]
            except:
                raise KeyError("Key Error. Did you get data?")
        return out
