#! /usr/bin/env python
# coding=utf8

# ECDSA BTC of FastSignVerify modified for Waas2 checker
# Copyright (C) 2014-2018  Antoine FERRON

# Some portions based on :
# "python-ecdsa" Copyright (C) 2010 Brian Warner (MIT Licence)
# "Simple Python elliptic curves and ECDSA" Copyright (C) 2005 Peter Pearson (public domain)
# "Electrum" Copyright (C) 2011 thomasv@gitorious (GPL)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


import os
from B58 import *
import binascii
import base64
import struct
import hmac
from ECDSA_256k1 import *
import cPickle as pickle

def load_gtable(filename):
	with open(filename, 'rb') as input:
		 global gtable
		 gtable = pickle.load(input)

def mulG(real):
	if real == 0: return INFINITY
	assert real > 0
	br=[]
	dw=16
	while real > 0 :
		dm = real%dw
		real = real - dm
		br.append( dm-1 )
		real = real>>4
	while len(br)<64: br.append(-1)
	kg=INFINITY
	for n in range(64):
		if br[n]>=0:
			precomp=gtable[n][br[n]]
			kg=kg+precomp
	return kg

def dsha256(message):
	hash1=hashlib.sha256(message).digest()
	return hashlib.sha256(hash1).hexdigest()
	

class Signature( object ):
  def __init__( self, pby, r, s ):
	self.r = r
	self.s = s
	self.pby = pby

  def encode(self):
	sigr = binascii.unhexlify(("%064x" % self.r).encode())
	sigs = binascii.unhexlify(("%064x" % self.s).encode())
	return sigr+sigs

class Public_key( object ):
  def __init__( self, generator, point ):
	self.generator = generator
	self.point = point
	n = generator.order()
	if not n:
	  raise RuntimeError, "Generator point must have order."
	if not n * point == INFINITY:
	  raise RuntimeError, "Generator point order is bad."
	if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
	  raise RuntimeError, "Generator point has x or y out of range."

  def verifies( self, hashe, signature ):
	if self.point == INFINITY: return False
	G = self.generator
	n = G.order()
	if not curve_256.contains_point(self.point.x(),self.point.y()): return False
	r = signature.r
	s = signature.s
	if r < 1 or r > n-1: return False
	if s < 1 or s > n-1: return False
	c = inverse_mod( s, n )
	u1 = ( hashe * c ) % n
	u2 = ( r * c ) % n
	xy =  self.point.dual_mult( u1, u2) # u1 * G + u2 * self.point
	v = xy.x() % n
	return v == r

class Private_key( object ):
  def __init__( self, secret_multiplier ):
	#self.public_key = public_key
	self.secret_multiplier = secret_multiplier

  def der( self ):
	hex_der_key = '06052b8104000a30740201010420' + \
				  '%064x' % self.secret_multiplier + \
				  'a00706052b8104000aa14403420004' + \
				  '%064x' % self.public_key.point.x() + \
				  '%064x' % self.public_key.point.y()
	return hex_der_key.decode('hex')

  def sign( self, hash, k ):
	G = generator_256 #self.public_key.generator
	n = G.order()
	p1 = mulG(k)
	r = p1.x()
	if r == 0: raise RuntimeError, "amazingly unlucky random number r"
	s = ( inverse_mod( k, n ) * ( hash + ( self.secret_multiplier * r ) % n ) ) % n
	if s == 0: raise RuntimeError, "amazingly unlucky random number s"
	if s > (n>>1): #Canonical Signature enforced (lower S)
		s = n - s
		pby = (p1.y()+1)&1
	else:
		pby = (p1.y())&1
	return Signature( pby, r, s )

def randoml(pointgen):
  cand = 0
  while cand<1 or cand>=pointgen.order():
	cand=int(os.urandom(32).encode('hex'), 16)
  return cand

def hash_msg(message):
	message=message.replace("\r\n","\n")
	lenmsg=len(message)
	if lenmsg<253: lm = bytearray(struct.pack('B',lenmsg))
	else: lm = bytearray(struct.pack('B',253)+struct.pack('<H',lenmsg)) # up to 65k
	#full_msg = bytearray("\x18Bitcoin Signed Message:\n")+ lm + bytearray(message,'utf8')
	full_msg = bytearray(message,'utf8')
	return dsha256(full_msg)

def bitcoin_verify(sigr, sigs, hash, publickey):
		G = generator_256
		order = G.order()
		#r = int(sigr,16)
		r = sigr
		#s = int(sigs,16)
		s = sigs
		assert r > 0 and r <= order-1
		assert s > 0 and s <= order-1
		p = curve_256.p()
		xcube = pow(r,3,p)
		exposa = (p+1)>>2
		beta = pow(xcube+7, exposa, p)
		R = Point(r, beta, order)
		R2 = Point(r, (p-beta)%order, order)
		output = 0
		try :
			check_sig_compute(hash, R,  s, publickey)
			output+=1
		except :
			check_sig_compute(hash, R2, s, publickey)
			output+=1
		return output

def check_sig_compute(hash, R, s, publickey):
		r = R.x()
		y = R.y()
		order = generator_256.order()
		# check R is on curve
		assert curve_256.contains_point(r,y)
		# checks that nR is at infinity
		assert order*R==INFINITY
		inv_r = inverse_mod(r,order)
		e = hash
		# Q = (sR - eG) / r
		Q = inv_r * (  R.dual_mult( -e % order, s ) )
		# checks Q in range, Q on curve, Q order
		pubkey = Public_key( generator_256, Q)
		# checks the point extracted is the signature point
		if pubkey.point.x() != publickey.point.x():
			raise Exception("Bad signature")
		# checks signature
		assert pubkey.verifies( e, Signature(0,r,s) )
		assert publickey.verifies( e, Signature(0,r,s) )
