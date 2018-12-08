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

import sys,os,_thread,time
from scapy import *
import random # Can remove after completion
import queue
import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl
import pyric.utils.channels as ch
import itertools
import optparse

def CurrentDate():
	Date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
	return Date

def banner():
	print("To kill this script hit CRTL-C")
	print("")

def FindLocalIP(Iface, OURIP):
	if Iface == 'ALL':
		return '0.0.0.0'

	try:
		if IsOsX():
			return OURIP
		elif OURIP == None:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.setsockopt(socket.SOL_SOCKET, 25, Iface+'\0')
			s.connect(("127.0.0.1",9))#RFC 863
			ret = s.getsockname()[0]
			s.close()
			return ret
		return OURIP
	except socket.error:
		print((color("[!] Error: %s: Interface not found" % Iface, 1)))
		sys.exit(-1)

def StartupMessage():
	print("")

def OsInterfaceIsSupported():
	if settings.Config.Interface != "Not set":
		return not IsOsX()
	return False

def IsOsX():
	return sys.platform == "darwin"

# Debugging Interfaces
def DebuggingInterface(iface):
	interfaces = pyw.interfaces()
	print(interfaces)
	print(("Is %s an interface? %s" % (iface, pyw.isinterface(iface))))
	print(("Is %s a wireless device? %s" % (iface,pyw.iswireless(iface))))
	w0 = pyw.getcard(iface)
	print(("Is %s active?  %s" % (iface, pyw.isup(w0))))
	print(("Is %s blocked? %s" % (iface, pyw.isblocked(w0))))
	iinfo = pyw.ifinfo(w0)
	print(iinfo)
	pinfo = pyw.phyinfo(w0)
	print((pinfo['bands']))

# Check Interfaces - Make sure there is at least two Wireless Cards that support Monitor Mode
def CheckInterfaces():
	if len(pyw.winterfaces()) < 2:
		return False
	else:
		return True

# Make sure the Interfaces that are being utilized are in Monitor Mode
def SetMonitorMode(iface,action):
	wcard = pyw.getcard(iface)
	# bring card down to ensure safe change
	pyw.down(wcard)

	if action == "monitor":
		# check to make sure the card isn't already in monitor mode
		if pyw.modeget(wcard) == 'monitor':
			print(("Card %s is already in monitor Mode" % str(iface)))
		else:
			print(("Putting card %s into monitor mode" % str(iface)))
			pyw.modeset(wcard,action)

	elif action == "managed":
		# check to make sure the card isn't already in managed mode
		if pyw.modeget(wcard) == 'managed':
			print(("Card %s is already in managed Mode" % str(iface)))
		else:
			print(("Putting card %s into managed mode" % str(iface)))
			pyw.modeset(wcard,action)
	else:
		print("Unrecongnized command")
	# Bring card back up, should now be changed.  
	pyw.up(wcard)


# Changes the Interface (typically of wlan1) to make sure it's listening for the EAPOL Packets. 
def SetIfaceChannel(iface,channel):
	if channel is None:
		print("Error with the channel still.  leaving")
		return 0
	else:	
		print(("Changing %s to channel %s" % (iface[1],int(channel))))
		try:
			pyw.chset(iface,int(channel), None)
		except:
			pyw.chset(iface,1)