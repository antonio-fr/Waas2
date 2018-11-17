#!/usr/bin/python2.7
# -*- coding: ascii -*-

# W(aaS)2 service checker
# Get a signature from W(aaS)2 service and check the provided signature
# W(aaS)2 is a service providing random valid signature for the first 
# Bitcoin coinbase. You can be a real con artist !
# Copyright (C) 2018  Antoine FERRON

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


import sys
from ECDSA_BTC import *
from ECDSA_256k1 import *
import base64
import RESTapi

load_gtable('G_Table')

print "\n W(aaS)2 checker v0.1 "
print "----------------------"
# The public key of the first Bitcoin coinbase output in block #0
# is 04
#    678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6
#    49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
px = int("678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6",16)
py = int("49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",16)
putkeypoint = Point(px, py, generator_256.order())
pubkeyobj = Public_key( generator_256, putkeypoint)

# Get signature from api.oxt.me/waas
try:
	waas_api = RESTapi.getRestJSON('https://api.oxt.me/waas')
	waas_api.getData()
	hash_message = int( waas_api.getKey("data/0/hash_message") )
	signature_r =  int( waas_api.getKey("data/0/signature_r")  )
	signature_s =  int( waas_api.getKey("data/0/signature_s")  )
except:
	print "Something were wrong while getting info from api.oxt.me/waas."
	print "Check your Internet connection or contact W(aaS)2 system admin."
	sys.exit(1)

print "W(aaS)2 service contacted :"
print " Hash = ",hash_message
print "  r =   ",signature_r
print "  s =   ",signature_s
print "Testing...\n"
try :
	result = bitcoin_verify(signature_r, signature_s, hash_message, pubkeyobj)
except:
	result = 0
if result == 1:
	print "Signature tests are all OK"
	print "Congrats, you're Satoshi Nakamoto! Please contact Twitter team to claim @satoshi account."
else:
	print "A signature test is bad"
	print "Sorry Craig, you're not Satoshi."
raw_input("\nPress Enter to quit...")
