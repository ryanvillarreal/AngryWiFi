import utils
import configparser
import subprocess

from utils import *

__version__ = 'AngryWifi 0.10'

class Settings:
	
	def __init__(self):
		self.AngryWifiPATH = './'

	def populate(self, options):
		# Config parsing
		config = configparser.ConfigParser()

def init():
	global Config
	Config = Settings()