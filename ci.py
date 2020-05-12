# Aleandro Andrea aaah1976@gmail.com
# 05/2020
#
# Arguments
# Pull data from Cisco Devices and return a formatted file.
#
# ci.py        -ip:192.168.1.1 [-u:user] [-o:file.txt]
# -t   Info request
#         -t:cdp
#         -t:interfaces
# -ip  IP of the Cisco device
# -u   User to log in
# -o   Output File. Default value "output.csv"


import getpass
import sys

from ciscoinfo import ssh, ciscoinfo


def check_args(args):
    # chk_arg
    #           [0] Boolean. True: Arguments are right, False: Missing or wrong  arguments.
    #           [1] String.   cdp: cdp report. interfaces: interfaces report.
    #           [2] String.   user: User that will be used to  login into devices.
    #           [3] String.   output: File name where data will be stored.

    ar_type = ar_ip = ar_user = ar_output = ''
    arg_sw = False
    for i in range(0, len(args)):
        y = args[i].lower()
        if '-t:' in y:
            ar_type = (y[y.find("-t:") + 3:])
        if '-p:' in y:
            ar_ip = (y[y.find("-ip:") + 4:])
        if '-u:' in y:
            ar_user = (y[y.find("-u:") + 3:])
        if '-o:' in y:
            ar_output = (y[y.find("-o:") + 3:])
    if ar_ip == '' or ar_type not in ['cdp', 'interfaces']:
        printarg()
        arg_sw = False
    else:
        arg_sw = True
    return [arg_sw, ar_type, ar_ip, ar_user, ar_output]


def printarg():
    print()
    print('Pull data from Cisco Devices and return a formatted file.')
    print()
    print("ci.py -t:'cdp'|'interfaces' -ip:192.168.1.1 [-u:user] [-o:file.txt]")
    print()
    print('-t   Info request')
    print('         -t:cdp')
    print('         -t:interfaces')
    print('-ip  IP of the Cisco device')
    print('-u   User to log in ')
    print('-o   Output File. Default value "output.csv"')


def main(argvs):
    chk_arg = check_args(argvs)
    if chk_arg[3] == '':
        chk_arg[3] = 'output.csv'
    if not chk_arg[0]:
        exit()
    if chk_arg[3] == '':
        chk_arg[3] = getpass.getuser()
    pw = getpass.getpass()
    con = ssh(chk_arg[2], chk_arg[3], pw)
    print('trying to connect ...')
    con.connect()
    cdp_info = ciscoinfo(chk_arg[2], con, chk_arg[3])
    print('status: {}.  result: {}'.format(cdp_info.cisco_status[0], cdp_info.cisco_status[1]))


if __name__ == "__main__":
    main(sys.argv)