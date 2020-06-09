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
#         -t:access
#
# -ip  IP of the Cisco device
# -u   User to log in
# -o   Output File. Default value "output.csv"


import sys
import ciscoinfo

if __name__ == "__main__":
    ciscoinfo.main(sys.argv)

#
# import getpass
# import sys
# import multiprocessing
# from ciscoinfo import ssh, ciscoinfo, ip_list, ciscopass, interfaces, cdp
#
#
# def check_args(args):
#     # Returns
#     #           [0] Boolean.    True        : Arguments are right, False: Missing or wrong  arguments.
#     #           [1] String.     cdp         : Cisco discovery protocol report.
#     #                           interfaces  : Interfaces report.
#     #                           access      : Try access to the device
#     #           [2] String.     IPs         : IP list.
#     #           [3] String.     user        : User that will be used to  login into devices.
#     #           [4] String.     output      : File name where data will be stored.
#     #
#
#     ar_type = ar_ip = ar_user = ar_output = ar_pass = ''
#     arg_sw = False
#     for i in range(0, len(args)):
#         y = args[i].lower()
#         if '-t:' in y:
#             ar_type = (y[y.find("-t:") + 3:])
#         if '-ip:' in y:
#             ar_ip = (y[y.find("-ip:") + 4:])
#             ar_ip = ip_list(ar_ip)
#         if '-u:' in y:
#             ar_user = (y[y.find("-u:") + 3:])
#         if '-o:' in y:
#             ar_output = (y[y.find("-o:") + 3:])
#         if '-p:' in y:
#             ar_pass = (args[i][args[i].find("-p:") + 3:])
#
#     if len(ar_ip) == 0 or ar_type not in ['cdp', 'interfaces', 'access']:
#         printarg()
#         arg_sw = False
#     else:
#         arg_sw = True
#     return [arg_sw, ar_type, ar_ip, ar_user, ar_pass, ar_output]
#
#
# def printarg():
#     print()
#     print('Pull data from Cisco Devices and return a formatted file.')
#     print()
#     print("ci.py -t:'cdp'|'interfaces' -ip:192.168.1.1 [-u:user] [-o:file.csv]")
#     print()
#     print('-t   Requested info')
#     print('         -t:cdp')
#     print('         -t:interfaces')
#     print('         -t:access')
#     print('-ip  IP of the Cisco device')
#     print('-u   User to log in ')
#     print('-o   Output File. Default value "output.csv"')
#
#
# def pull_data(ctype, ip, user, pw, filename, verbose):
#     filename = filename[0:filename.rfind('.')] + '_' + ip + filename[filename.rfind('.'):]
#     cdp_info = ciscoinfo
#     # con = ssh(ip=ip, user=user, pw=pw, verbose=verbose)
#     # print('Connecting to : {}'.format(ip))
#     # con.connect()
#     # if con.status[0] > 0:
#     #     print('Pulling data ...')
#     # # '10.70.0.100', 'nclchk', 'BugC@tch3r$', 'nofile'
#     print('Processing IP:', ip)
#     if ctype == "interfaces":
#         cdp_info = interfaces(ip=ip, user=user, pw=pw, file=filename)
#     elif ctype == "cdp":
#         cdp_info = cdp(ip=ip, user=user, pw=pw, file=filename)
#     print('Done IP:', ip, cdp_info.status)
#
#
# def main(argvs):
#     chk_arg = check_args(argvs)
#     if chk_arg[5] == '':
#         chk_arg[5] = 'output.csv'
#     if not chk_arg[0]:
#         exit()
#     if len(chk_arg[3]) == 0:
#         chk_arg[3] = getpass.getuser()
#     if len(chk_arg[4]) == 0:
#         chk_arg[4] = getpass.getpass()
#     main_type = chk_arg[1]
#     main_ip = chk_arg[2]
#     main_user = chk_arg[3]
#     main_pw = chk_arg[4]
#     main_output = chk_arg[5]
#     jobs = []
#     if main_type == 'access':
#         main_access = ciscopass(main_ip, main_user, main_pw, main_output)
#     if main_type in ['cdp', 'interfaces']:
#         for i in main_ip:
#             multicon = multiprocessing.Process(target=pull_data,
#                                                args=(main_type, i, main_user, main_pw, main_output, True,))
#             jobs.append(multicon)
#             multicon.start()
#
#
# if __name__ == "__main__":
#     main(sys.argv)
