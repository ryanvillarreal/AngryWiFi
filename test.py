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
import Angry

if __name__ == "__main__":
	print "main"
	iface = 'wlan1'
	iface = pyw.getcard(iface)
	print iface[1]