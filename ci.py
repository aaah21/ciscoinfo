# Aleandro Andrea aaah1976@gmail.com
# 05/2020
#
# Arguments
# Pull data from Cisco Devices and return a formatted file.
#
# ci.py        -ip:192.168.1.1-192.168.1.100 [-u:user] [-o:file.txt]
# -t   Info request
#         -t:cdp
#         -t:interfaces
# -ip  IP of the Cisco device
# -u   User to log in
# -o   Output File. Default value "output.csv"


import getpass
import sys
import multiprocessing
from ciscoinfo import ssh, ciscoinfo, ip_list


def check_args(args):
    # Returns
    #           [0] Boolean.    True  : Arguments are right, False: Missing or wrong  arguments.
    #           [1] String.     cdp   : cdp report. interfaces: interfaces report.
    #           [2] String.     IPs   : IP list.
    #           [3] String.     user  : User that will be used to  login into devices.
    #           [4] String.     output: File name where data will be stored.
    #

    ar_type = ar_ip = ar_user = ar_output = ''
    arg_sw = False
    for i in range(0, len(args)):
        y = args[i].lower()
        if '-t:' in y:
            ar_type = (y[y.find("-t:") + 3:])
        if '-ip:' in y:
            ar_ip = (y[y.find("-ip:") + 4:])
            ar_ip = ip_list(ar_ip)
        if '-u:' in y:
            ar_user = (y[y.find("-u:") + 3:])
        if '-o:' in y:
            ar_output = (y[y.find("-o:") + 3:])
    if len(ar_ip) == 0 or ar_type not in ['cdp', 'interfaces']:
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


def pull_data(ctype, ip, user, pw, filename, verbose):
    filename = filename[0:filename.rfind('.')] + '_' + ip + filename[filename.rfind('.'):]
    cdp_info = ciscoinfo
    con = ssh(ip=ip, user=user, pw=pw, verbose=verbose)
    print('Connecting to : {}'.format(ip))
    con.connect()
    if con.status[0] > 0:
        print('Pulling data ...')
    cdp_info = ciscoinfo(type=ctype, ssh=con, file=filename)
    print('{} Result: {}'.format(ip, cdp_info.status[1]))


def main(argvs):
    chk_arg = check_args(argvs)
    if chk_arg[4] == '':
        chk_arg[4] = 'output.csv'
    if not chk_arg[0]:
        exit()
    if chk_arg[3] == '':
        chk_arg[3] = getpass.getuser()
    pw = getpass.getpass()

    jobs = []
    for i in chk_arg[2]:
        multicon = multiprocessing.Process(target=pull_data, args=(chk_arg[1], i, chk_arg[3], pw, chk_arg[4], True,))
        jobs.append(multicon)
        multicon.start()


if __name__ == "__main__":
    main(sys.argv)
