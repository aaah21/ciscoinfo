# Aleandro Andrea aaah1976@gmail.com
# 05/2020
#
# Arguments
# Pull data from Cisco Devices and return a formatted file.
#
# ci.py        -ip:192.168.1.1-192.168.1.100 [-u:user] [-o:file.txt]
# -t   Info request
#         -t:cdp
#         -t:lldp
#         -t:interfaces
#         -t:access
#
# -ip  IP of the Cisco device
# -u   User to log in
# -o   Output File. Default value "output.csv"


import sys
import ciscoinfo


if __name__ == "__main__":
    ciscoinfo.main(sys.argv)
