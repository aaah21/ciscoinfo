import sys
import pprint
from os import path
import ipaddress
import getpass

from sshlib import ssh


def convertcdp(cdp):
    cdp_lines = []
    cdp_result = []
    cdp_device = cdp_ip = cdp_platform = cdp_capabilities = cdp_interface1 = cdp_interface2 = cdp_version = ''
    for i in cdp:
        cdp_lines.append(i.rstrip())
    for i in range(0, len(cdp_lines) - 1):
        if not len(cdp_lines[i]) > 0:
            next
        y = cdp_lines[i]
        z = ''
        if i > 0:
            z = cdp_lines[i + 1]
        if ("--------" in y and i > 0) or i == len(cdp_lines) - 2:
            cdp_item = [cdp_device, cdp_ip, cdp_platform, cdp_capabilities, cdp_interface1, cdp_interface2, cdp_version]
            if len(cdp_device)>0:
                cdp_result.append(cdp_item)
        if "--------" in y:
            cdp_device = cdp_ip = cdp_platform = cdp_capabilities = cdp_interface1 = cdp_interface2 = cdp_version = ''
            cdp_item = []
        if "device id:" in y.lower():
            cdp_device = (y[11:])
        if "ip address:" in y.lower():
            cdp_ip = (y[14:])
        if "platform: " in y.lower():
            cdp_platform = (y[10:(y.find(","))])
        if "platform: " in y.lower():
            cdp_capabilities = (y[y.find("ties:") + 6:])
        if "interface: " in y.lower():
            cdp_interface1 = (y[11:(y.find(","))])
        if "outgoing port" in y.lower():
            cdp_interface2 = (y[y.find("port") + 7:])
        if "version :" in y.lower():
            cdp_version = z
    return cdp_result


def readfile(filename):
    fileobj = ''
    filetext = ''
    if path.exists(filename):
        fileobj = open(filename, 'r')
        filetext = fileobj.readlines()
        fileobj.close()
    else:
        filetext = "File does not exist"
    return filetext


def savefile(filename, lines_list, headers_list):
    header = ''
    for i in range(0, len(headers_list)):
        header = header + '"' + headers_list[i] + '"'
        if i != len(headers_list) - 1:
            header = header + ","
    header = header + '\n'
    try:
        file1 = open(filename, "w")
    except Exception as e:
        return False, e
    file1.writelines(header)

    for i in range(0, len(lines_list)):
        line = ''
        for y in range(0, len(lines_list[i])):
            line = line + '"' + lines_list[i][y] + '"'
            if y != len(lines_list[i]) - 1:
                line = line + ','
        line = line + '\n'
        file1.writelines(line)
    file1.close
    return True, "File Saved!!!"


def printarg():
    print()
    print('Pull CDP data from switch and return a formatted file.')
    print()
    print('ciscocdp.py -ip:192.168.1.1 [-u:user] [-o:file.txt]')
    print()
    print('-ip          IP of the Cisco device')
    print('-u           User to log in ')
    print('-o           Output File. Default value "cdp.csv"')


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


def main(argvs):
    chk_arg = check_args(argvs)
    if chk_arg[3] == '':
        chk_arg[3] = 'cdp.csv'
    if not chk_arg[0]:
        exit()
    if chk_arg[2] == '':
        chk_arg[2] = getpass.getuser()
    pw = getpass.getpass()
    con = ssh(chk_arg[1], chk_arg[2], pw)
    print('trying to connect ...')
    con.connect()
    if con.ssh_status[0] > 0:
        cdp_result = con.execute('show cdp nei detail')
        print('Pulling Data ...')
        cdp_result = convertcdp(cdp_result)
        print('Pulled {} Devices.'.format(len(cdp_result)))
        print('Saving Data in file: {}'.format(chk_arg[3]))
        cdp_save = savefile(chk_arg[3], cdp_result, ['Hostname', 'IP', 'Platform', 'Capabilities', 'Local Interface',
                                                     'Remote Interface', 'Version'])
        print(cdp_save[1])
        if not cdp_save[0]:
            exit()
    else:
        print(con.ssh_status[1])


if __name__ == "__main__":
    main(sys.argv)
