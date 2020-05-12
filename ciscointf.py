# Aleandro Andrea aaah1976@gmail.com
# 05/2020
#
# Arguments
# Pull CDP data from switch and return a formatted file.
# ciscocdp.py -ip:192.168.1.1 [-u:user] [-o:file.txt]
# -ip          IP of the Cisco device
# -u           User to log in
# -o           Output File. Default value "cdp.csv"

import getpass
import sys

from ciscoinfo import ssh, ciscoinfo


def check_args(args):
    ip = ''
    user = ''
    output = ''
    for i in range(0, len(args)):
        y = args[i].lower()
        if '-p:' in y:
            ip = (y[y.find("-p:") + 3:])
        if '-u:' in y:
            user = (y[y.find("-u:") + 3:])
        if '-o:' in y:
            output = (y[y.find("-o:") + 3:])
    if ip == '':
        printarg()
        return [False, ip, user, output]
    return [True, ip, user, output]


def printarg():
    print()
    print('Pull Interface info  data from switch and return a formatted file.')
    print()
    print('ciscointf.py -ip:192.168.1.1 [-u:user] [-o:file.txt]')
    print()
    print('-ip          IP of the Cisco device')
    print('-u           User to log in ')
    print('-o           Output File. Default value "interfaces.csv"')


def main(argvs):
    chk_arg = check_args(argvs)
    if chk_arg[3] == '':
        chk_arg[3] = 'interfaces.csv'
    if not chk_arg[0]:
        exit()
    if chk_arg[2] == '':
        chk_arg[2] = getpass.getuser()
    pw = getpass.getpass()
    con = ssh(chk_arg[1], chk_arg[2], pw)
    print('trying to connect ...')
    con.connect()
    intf_info = ciscoinfo('interfaces', con, chk_arg[3])
    print('status: {}.  result: {}'.format(intf_info.cisco_status[0], intf_info.cisco_status[1]))


if __name__ == "__main__":
    # Arguments
    # Pull Interface info  data from switch and return a formatted file.
    # ciscointf.py -ip:192.168.1.1 [-u:user] [-o:file.txt]
    # -ip          IP of the Cisco device
    # -u           User to log in
    # -o           Output File. Default value "cdp.csv"
    main(sys.argv)