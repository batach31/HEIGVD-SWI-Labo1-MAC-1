#! /usr/bin/env python

# sources:
# https://www.thepythoncode.com/article/create-fake-access-points-scapy
# https://pynative.com/python-generate-random-string/
# https://pymotw.com/2/threading/

from scapy.all import *
import sys
import os
import threading
import random
import string

# interface (to be modified by the user)
iface = "wlan0mon"

# array of fake AP threads
threads = []

# function to simulate a fake ap with name 'ssid'
def fake_ap(ssid):

	# random fake mac address
	src_mac = RandMAC()

	# 802.11 with destination MAC as broadcast
	dot11 = Dot11(type = 0, subtype = 8, addr1 = "ff:ff:ff:ff:ff:ff", addr2 = src_mac, addr3 = src_mac)

	# beacon
	beacon = Dot11Beacon()

	# packet to send
	packet = RadioTap()/dot11/beacon/Dot11Elt(ID = "SSID", info = ssid, len = len(ssid))

	# sending the packet 10 times per second in and infinit loop
	sendp(packet, inter = 0.1, iface = iface, loop = 1)

# start a new Thread with given ssid
def start_fake_ap_thread(ssid):
	thread = threading.Thread(target = fake_ap, args = (ssid,))
	threads.append(thread)
	thread.start()

# function to generate a random ssid name with given size
def random_ssid_name(size = 8):
	return ''.join(random.choice(string.ascii_lowercase) for i in range(size))

if len(sys.argv) - 1 == 1:
	param = sys.argv[1]

	# in case the argument is a digit
	if param.isdigit():

		n = int(param)

		for i in range(n):
			ssid = random_ssid_name()
			print("{} - ssid : {}".format(i, ssid))
			start_fake_ap_thread(ssid)
	else:

		# in case the argument is a file path
		if not os.path.isfile(param):
			print("Invalid path : {}".format(param))
			sys.exit()

		fp = open(param)

		line = fp.readline()

		while line:
			print("ssid : {}".format(line))
			start_fake_ap_thread(line)
			line = fp.readline()
			
		fp.close()
else:
	print("please enter a file name with ssids to fake or a number of ssids to generate randomly.")
	




