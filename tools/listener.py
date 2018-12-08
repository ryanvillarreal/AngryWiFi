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


# Probing will continually sniff for new Beacons and EAPOL while recording in pcap file.
# Dang Scapy won't let me find the Channel from Dot11elt packet by ID.  I have to iterate through it. 
def ProbingBeacons(pkt) :
  channel = ""
  if pkt.haslayer(Dot11) :
		if pkt.haslayer(Dot11Beacon):
			beacon_pktdump.write(pkt)
			try: 
				channel = int(ord(pkt[Dot11Elt:3].info))
			except: 
				print("Error with the channel")
			
			if pkt.addr2 not in ap_list:
				ap_list.append(pkt.addr2)
				if play_nice == True:
					PlayNice(pkt.addr2,channel)
				else:
					attack_queue.put((pkt.addr2,channel))

# Temporary to split up the WLAN interfaces
def ProbingEAPOLs(pkt) :
  attck_channel = ""
  if pkt.haslayer(Dot11) :
		if pkt.haslayer(Dot11Auth) or pkt.haslayer(Dot11Beacon):
			attack_pktdump.write(pkt)
			attack_channel = str(ord(pkt[Dot11Elt:3].info))
			#print "BSSID: %s , Channel: %s" % (pkt.addr2,channel)
			if pkt.addr2 not in ap_list:
				ap_list.append(pkt.addr2)
				if play_nice == True:
					PlayNice(pkt.addr2,attack_channel)
				else:
					attack_queue.put((pkt.addr2,attack_channel))

# Scapy's Sniffing service - wlan0 should be the primary card for sniffing.
def SniffingBeacons(iface):
	sniff(iface=iface, prn=ProbingBeacons, store=0)

def SniffingHandshakes(iface):
	sniff(iface=iface, prn=ProbingEAPOLs, store=0)

def HiddenSSID():
	#Check to see if it's a hidden SSID
	essid = pkt[Dot11Elt].info if '\x00' not in pkt[Dot11Elt].info and pkt[Dot11Elt].info != '' else 'Hidden SSID'
	bssid = pkt[Dot11].addr3
	client = pkt[Dot11].addr2

# TimeSink will add APs to Queue as seen and pop them off as completed. 
def TimeSink():
	while True:
		if attack_queue.empty():
			time.sleep(5)
		elif not attack_queue.empty():
			GetAngry(attack_queue.get())
		else:
			print("Something went wrong")