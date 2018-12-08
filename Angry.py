#!/usr/bin/env python
# This file is part of AngryWifi Package
# Original work by Ryan Villarreal 
#
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

import optparse
from utils import *

banner()

parser = optparse.OptionParser(usage='python %prog -I eth0 -w -r -f\nor:\npython %prog -I eth0 -wrf', version=settings.__version__, prog=sys.argv[0])
parser.add_option('-v','--verbose',action="store_true", help="Increase verbosity.", dest="Verbose")
options, args = parser.parse_args()

if not os.geteuid() == 0:
    print (color("[!] AngryWifi must be run as root."))
    sys.exit(-1)
elif IsOsX() is True:
    print ("\n\033[1m\033[31mOSX is not supported by the PyRic package. \033[0m\n") # This option should be changed to True upon completion of development. 
    exit(-1)

StartupMessage()

def main():
	try:
		# start the main
		print("Starting AngryWifi")

		while True:
			time.sleep(1)

	except KeyboardInterrupt:
		sys.exit("Exiting...")

if __name__ == '__main__':
	main()
