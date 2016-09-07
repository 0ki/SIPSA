#!/usr/bin/env python
# SIPSAc4 - Source IP spoofing for anonymization over UDP (IPv4 sender)
# (C) Kirils Solovjovs, 2016; Modified BSD licence

# WARNING WARNING WARNING
# 
# This is a proof of concept tool. Do not depend on it for confidentiality,
# anonimity or deniablity. Do not expect the tool to preserve the integrity
# of your data or provide any reasonable level of availability for that matter.
# This is a proof of concept tool.
# 
# WARNING WARNING WARNING

# This demo supports IPv4 only, but there is no reason why this shouldn't work for IPv6


# How many sources and destinations to create? Total pairs = srcR x dstR
srcR=5
dstR=3

# Shared key used to perform AES encryption on SIPSA metadata *only*
key="YOUR SHARED KEY HERE"


import os,sys

if not os.geteuid() == 0:
	sys.exit("ERR: Peril awaits you, seeing you need to be root to craft packets. Quitting.")
	
from scapy.all import *
import random
from struct import unpack
from socket import AF_INET, inet_pton, inet_aton
from Crypto.Cipher import AES
from Crypto import Random
from hashlib import md5


key=md5(key).digest() #always exactly 32 bytes

	
# privateIP(): is IPv4 address private or loopback?
# function from http://stackoverflow.com/questions/691045 , author: jackdoe
def privateIP(ip):	 
    f = unpack('!I',inet_pton(AF_INET,ip))[0]
    private = (
        [ 2130706432, 4278190080 ], # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [ 3232235520, 4294901760 ], # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [ 2886729728, 4293918720 ], # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [ 167772160,  4278190080 ], # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
    ) 
    for net in private:
        if (f & net[1]) == net[0]:
            return True
    return False
    
    
# genIPs(): generate a list pseudo-random IPs
def genIPs(base,count):
	baseOct=base.split('.')
	avoid3=baseOct[3]
	if (count<2):
		sys.exit("ERR: You should always generate at least two IPs.")
	lst=[]
	lst.append(base) # inclose original IP
	while avoid3==baseOct[3]: #include
			baseOct[3]=str(random.randrange(1,255)) # 1-254 just to be safe 
	lst.append(".".join(baseOct)) #same subnet
	
	
	# WARNING! Please DO this if your base IP is in private space *and* NATted:
	# Swap comments on the next two lines to disable/enable full hiding of original source IP
	# lst=[]
	count=count-2
	
	
	while count>0:
		baseOct[0]=str(random.randrange(1,240)) # 1 - 239 , no multicast
		baseOct[1]=str(random.randrange(0,256)) # 0 - 255
		baseOct[2]=str(random.randrange(0,256)) # 0 - 255
		baseOct[3]=str(random.randrange(1,255)) # 1 - 254 , yes, it's crude
		if privateIP(".".join(baseOct)): # ignore private IPs
			continue
		count=count-1
		lst.append(".".join(baseOct))
		avoid3=baseOct[3]
		while avoid3==baseOct[3] and count>0: #include
			baseOct[3]=str(random.randrange(1,255)) # 1-254 just to be safe 
		if count>0:
			lst.append(".".join(baseOct)) #same subnet
			count=count-1
	return lst
	
	
# send_sipsa(): send a SIPSA packet
def send_sipsa(dstA,data,key="",pSrcIPlst=None,pDstIPlst=None):
	random.seed(dstA+realSrcIP+key+"."+str(srcR)+"."+str(dstR)) # always the same set of IP addresses
	if pSrcIPlst:
		srcIPlst=pSrcIPlst
	else:
		srcIPlst=genIPs(realSrcIP,srcR)
		random.shuffle(srcIPlst)
	if pDstIPlst:
		dstIPlst=pDstIPlst
	else:
		dstIPlst=genIPs(dstA,dstR)
		random.shuffle(dstIPlst)

	# WARNING! This crypto is likely not secure. Do not use in production!
	iv=Random.new().read(16)

	cipher=AES.new(key,AES.MODE_CBC,iv)
	metadata=inet_aton(realSrcIP)+inet_aton(dstA)+"".join([inet_aton(e) for e in srcIPlst])+"\xff"+"".join([inet_aton(e) for e in dstIPlst])+"\xff"
	
	# we can also hide the real IP from the server. it will still work:
	# metadata="\x00"*8+"".join([inet_aton(e) for e in srcIPlst])+"\xff"+"".join([inet_aton(e) for e in dstIPlst])+"\xff"
	
	crypto=iv+cipher.encrypt(metadata.ljust(len(metadata) + 16 - len(metadata) % 16,"\x00"))
	lenIndicator=len(crypto)/16
	if lenIndicator>255:
		sys.exit("ERR: Too many sources and/or dests.") # size field is currently limited to 1 byte
		
	payload="SIPSA\x00\x04"+chr(lenIndicator)+crypto+str(data) #Layer5 payload
	
	# send from and to all the addresses
	for srcIP in srcIPlst:
		for dstIP in dstIPlst:
			packet = Ether()/IP(src=srcIP,dst=dstIP)/UDP(sport=51654,dport=51654)/payload
			sendp(packet,iface=routingIface, verbose=0)
			
	print "Sent",len(srcIPlst)*len(dstIPlst),"packets."


routes=[]
for routeentry in conf.route.routes:
	if routeentry[0]==0:
		routes.append([routeentry[4],routeentry[3]])

if len(routes)<1:
	sys.exit("ERR: No IPv4 routes found.")

realSrcIP=routes[0][0]
routingIface=routes[0][1]

if len(routes)>1:
	sys.stderr.write("WARN: Multiple IPv4 routes found.\n")
	
print "Choosing "+routingIface+". "+realSrcIP+" is our real source IP."
	
if privateIP(realSrcIP):
	sys.exit("ERR: This PoC will not work behind NAT. Remove this warning (in code), if you are testing the tool on internal network.")

# Test:
send_sipsa("203.0.113.3",IP(src="8.8.8.8",dst="8.8.4.4")/TCP(sport=1234,dport=2000)/"Tunneled Layer 5 data",key)
