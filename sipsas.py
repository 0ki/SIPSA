#!/usr/bin/env python
# SIPSAs4 - Source IP spoofing for anonymization over UDP (IPv4 receiver)
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

# Please make sure that all other UDP ports on your systems are FILTERED (not REJECTED)


# Shared key used to perform AES encryption on SIPSA metadata *only*
key="YOUR SHARED KEY HERE"

import socket,re,sys
from Crypto.Cipher import AES
from hashlib import md5
from socket import inet_ntoa

key=md5(key).digest() #always exactly 32 bytes

UDPSock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
listen_addr = ("",51654) #listen on all interfaces, port 51654
UDPSock.bind(listen_addr)
while True:
	payload,[ip,port] = UDPSock.recvfrom(65535) #larger than actually
	print "Got a datagram from "+ip+".",
	if port!=51654:
		sys.stderr.write("Wrong source port ("+str(port)+").")
		continue
	if len(payload)<5+3+16:
		sys.stderr.write("Datagram too short to be SIPSA.")
		continue
	if not re.match("SIPSA",payload): #does the payload begin with "SIPSA"?
		sys.stderr.write("Not a SIPSA packet.")
		continue
	if payload[5:7]!="\x00\x04":
		sys.stderr.write("SIPSA version mismatch.")
		continue
	
	try:
		lenIndicator=ord(payload[7]) #how long is the metadata (in blocks of 16)
		rawdata=payload[8:8+lenIndicator*16]
		data=payload[8+lenIndicator*16:]
		iv=rawdata[:16]
		crypto=rawdata[16:]
		cipher = AES.new(key,AES.MODE_CBC,iv)
		metadata = cipher.decrypt(crypto)
		realSrcIP=inet_ntoa(metadata[0:4]) # real src
		realDstIP=metadata[4:8] # real dst
		srcIPlst=[]
		dstIPlst=[]
		i=8
		while metadata[i]!="\xff": #marker that indicates end of source list
			srcIPlst.append(metadata[i:i+4])
			i = i + 4
		i = i + 1	
		while metadata[i]!="\xff": #marker that indicates end of dest list
			dstIPlst.append(metadata[i:i+4])
			i = i + 4
				
	except:
		sys.stderr.write("Packet damaged. (maybe the key is mismatched?)\n")
		continue
	if ip==realSrcIP:
		realSrcIP=realSrcIP+"(ip match)"
		# I suggest adding a randomized ~100ms delay before sending the reply
		# reply only once per each packet, not each copy.
		# if realSrcIP is anonymized, do this for each unique "iv" and/or "crypto" 
		# send_sipsa(realDstIP,IP()/TCP(),key,srcIPlst,dstIPlst) # send the reply
		print "IP", realSrcIP, "sent us this:", data
	else:
		print

