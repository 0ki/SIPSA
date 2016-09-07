SIPSA
======
Source IP spoofing for anonymization over UDP

Source IP spoofing anonymization over UDP (SIPSA) is a proposal for a protocol that in many network environments would allow two hosts on the network to hide both their source and destination addresses, while still being able to communicate information.


This is a proof of concept tool that implements the SIPSA protocol. Use in production environments is highly discouraged. Do not depend on it for confidentiality, anonimity or deniablity. Do not expect the tool to preserve the integrity of your data or provide any reasonable level of availability for that matter.

You are welcome to fork and experiment!

* sipsas.py - IPv4 receiver
* sipsac.py - IPv4 sender
