# Aleandro Andrea aaah1976@gmail.com
# 05/2020
#
# ciscoinfo
#       Arguments:
#           cisco_type: String. cdp, interfaces, access, script
#           cisco_ssh : ciscoinfo.ssh. ssh class
#           cisco_file: String. Name of file for output.
#
# ssh
#       Arguments:
#           ip      : String. Device's IP
#           user    : String. User to login.
#           pw      : String. Password to login
#           verbose : Boolean.
#
# cdp.
#       Arguments:
#           ip      : String. Device's IP
#           user    : String. User to login.
#           pw      : String. Password to login
#       Returns:
#           object.status = list with status
#           object.result = list with cdp info
#
# interfaces.
#       Arguments:
#           ip      : String. Device's IP
#           user    : String. User to login.
#           pw      : String. Password to login
#       Returns:
#           object.status = list with status
#           object.result = list with interfaces info
#
# ciscopass.
#        Arguments:
#              ip:      String. List of valid IPs addresses
#              user:    String. List of Usernames used to connect. Comma separated.
#              pw:      String. List of Passwords used to connect. Comma separated.
#
# script. ** pending **
#        Arguments:
#              ip:      String. List of valid IPs addresses
#              user:    String. List of Usernames used to connect. Comma separated.
#              pw:      String. List of Passwords used to connect. Comma separated.
#
#


import time
import paramiko
import ipaddress
import getpass
import sys
import multiprocessing
from datetime import datetime
from os import path
from diagrams import Cluster, Diagram
from diagrams.generic.network import Switch
import csv


class script(object):
    def __init__(self, ip: str, user: str, pw: str, file: str):
        # Parameters ip, user and pw.
        #   ip:      String. List of valid IPs addresses
        #   user:    String. List of Usernames used to connect. Comma separated.
        #   pw:      String. List of Passwords used to connect. Comma separated.
        #
        self.status = [0, '']
        self.result = multiprocessing.Queue()
        user = user.split(',')
        pw = pw.split(',')
        if len(ip) == 0 or len(user) == 0 or len(pw) == 0:
            return
        index_worker = 0
        index_count = 0
        index_max = len(user) * len(pw) * len(ip)
        jobs = []
        print()
        for user_worker in user:
            for pw_worker in pw:
                print("Testing...  {:.2f}% Completed".format(index_count / index_max * 100))
                for ip_worker in ip:
                    index_worker = index_worker + 1
                    index_count = index_count + 1
                    if index_worker == 15:
                        time.sleep(20)
                        index_worker = 0
                    multicon = multiprocessing.Process(target=self.run,
                                                       args=(ip_worker, user_worker, pw_worker))
                    jobs.append(multicon)
                    multicon.start()
        multicon.join()
        result = ""
        swresult = False
        while not self.result.empty():
            result = result + " " + self.result.get()
            swresult = True
        self.status = [swresult, result]


class ssh(object):
    def __init__(self, ip, user, pw, verbose):
        # parameters IP, User, password and Verbose.
        #              ip:      String. Valid IP address
        #              user:    String. Username used to connect
        #              pw:      String. Password used to connect
        #              Verbose: Boolean. True shows progress in console.
        #
        # status[0] = -2    SSH Connection. Failed Authentication
        # status[0] = -1    SSH Host does not respond
        # status[0] = 0     SSH initial status
        # status[0] = 1     SSH Established. SSH User Mode
        # status[0] = 2     SSH Established. Privilege Mode
        #
        # status[1]         SSH Message.
        #
        self.ip = ip
        self.user = user
        self.pw = pw
        self.status = [0, '']
        self.socket = paramiko.SSHClient()
        self.socket.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.channel = self.socket.invoke_shell
        self.verbose = verbose

    def connect(self):
        if self.verbose:  # verbose on
            print('Opening SSH Connection...')
        try:
            self.socket.connect(self.ip, port=22, username=self.user, password=self.pw)
        except paramiko.ssh_exception.AuthenticationException as e:
            self.status = [-2, 'SSH Connection. Failed Authentication']
            return
        except:
            if self.verbose:  # verbose on
                print('SSH Host does not respond.')
            self.status = [-1, 'SSH Host does not respond.']
            return
        self.channel = self.socket.invoke_shell()
        chda = self.readssh()
        chda = str(chda)
        if '>' in chda[-5:]:
            self.status = [1, 'SSH User Mode']
            if self.verbose:  # verbose on
                print('SSH Established. User Mode.')
            return
        elif '#' in chda[-5:]:
            self.status = [1, 'SSH Privilege Mode']
            if self.verbose:  # verbose on
                print('SSH Established. Privilege Mode .')
            return

    def close(self):
        self.socket.close()

    def readssh(self):
        output = b''
        nonewdatacount = 0
        while True:
            time.sleep(2)
            nonewdatacount = nonewdatacount + 1
            if self.channel.recv_ready():
                nonewdatacount = 0
                readlines = self.channel.recv(65535)
                if len(readlines) == 0:
                    break
                output = output + readlines
                if self.verbose:  # verbose on
                    print("    Pulled {} Bytes".format(len(output)))
            if nonewdatacount > 2:
                break
        return output

    def execute(self, command):
        output = b''
        command = 'terminal length 0 \n' + command
        self.channel.send(command)
        self.channel.send('\n')
        if self.verbose:  # verbose on
            print('Executing Commands...')
        time.sleep(1)
        output = self.readssh()
        output = streamtolines(output)
        return output


class ciscopass(object):
    def __init__(self, ip: str, user: str, pw: str):
        # Parameters ip, user and pw.
        #   ip:      String. List of valid IPs addresses
        #   user:    String. List of Usernames used to connect. Comma separated.
        #   pw:      String. List of Passwords used to connect. Comma separated.
        #
        self.status = [0, '']
        self.result = multiprocessing.Queue()
        user = user.split(',')
        pw = pw.split(',')
        if len(ip) == 0 or len(user) == 0 or len(pw) == 0:
            return
        index_worker = 0
        index_count = 0
        index_max = len(user) * len(pw) * len(ip)
        jobs = []
        print()
        for user_worker in user:
            for pw_worker in pw:
                print("Testing...  {:.2f}% Completed".format(index_count / index_max * 100))
                for ip_worker in ip:
                    index_worker = index_worker + 1
                    index_count = index_count + 1
                    if index_worker == 15:
                        time.sleep(20)
                        index_worker = 0
                    multicon = multiprocessing.Process(target=self.run,
                                                       args=(ip_worker, user_worker, pw_worker))
                    jobs.append(multicon)
                    multicon.start()
        multicon.join()
        result = ""
        swresult = False
        while not self.result.empty():
            result = result + " " + self.result.get()
            swresult = True
        self.status = [swresult, result]

    def run(self, ip: str, user: str, pw: str):
        con = ssh(ip=ip, user=user, pw=pw, verbose=False)
        self.status = 'Connecting to : {}'.format(ip)
        con.connect()
        self.status = con.status
        if con.status[0] == 1:
            self.result.put("IP: " + ip + " " + user + " " + pw + " Result: " + con.status[1])
        con.close()


class ciscoinfo(object):
    def __init__(self, type, ssh: ssh):
        # parameters cisco_type, cisco_ssh, cisco_file
        #
        # cisco_type    Information that will be pulled
        #   Values:
        #               'cdp'             cdp report
        #               'lldp'            lldp report
        #               'interfaces'      interfaces report
        #
        # ssh Object    SSH object with an active connection to an end-point
        # cisco_file     file name where results will be saved.
        #
        self.type = type
        self.ssh = ssh
        self.data = []
        self.status = [-1, 'Unknown Issue']
        self.result = []
        self.run()

    def run(self):
        run_command = ''
        if self.ssh.status[0] > 0:
            # Commands and Headers to save files
            if self.type == 'cdp':
                run_command = 'show cdp nei detail'
            if self.type == 'lldp':
                run_command = 'show lldp nei detail'
            if self.type == 'interfaces':
                run_command = 'show interfaces\n show interfaces status\n show vlan'
            # Commands and Headers to save files ######################################
            self.result = self.ssh.execute(run_command)
            self.status = [0, 'Pulling Data ...']
            if self.type == 'cdp':
                self.result = convertcdp(self.result)
            if self.type == 'lldp':
                self.result = convertlldp(self.result)
            if self.type == 'interfaces':
                self.result = convertintf(self.result)

            self.status = [1, 'Pulled {} Lines.'.format(len(self.result))]
            self.status[1] = self.status[1] + '.'
        else:
            self.status = [-1, self.ssh.status[1]]


class neighbor(object):
    def __init__(self, proto, ip, user, pw, file):
        if not file:
            file = proto + ".csv"
        self.proto = proto
        self.ip = ip
        self.user = user
        self.pw = pw
        self.file = file  # nofile value will not save anyfile.
        self.status = ''
        self.result = ''
        run_header = ['Hostname', 'IP', 'Platform', 'Capabilities', 'Local Interface', 'Remote Interface',
                      'Version']
        neighbor_info = ciscoinfo
        con = ssh(ip=self.ip, user=self.user, pw=self.pw, verbose=False)
        self.status = 'Connecting to : {}'.format(ip)
        con.connect()
        if con.status[0] > 0:
            self.status = 'Pulling data ...'
        if self.proto == "cdp":
            neighbor_info = ciscoinfo(type='cdp', ssh=con)
        if self.proto == "lldp":
            neighbor_info = ciscoinfo(type='lldp', ssh=con)

        self.result = neighbor_info.result
        if not self.file == 'nofile':
            save = savefile(self.file, self.result, run_header)
        self.status = ip + ' Result: ' + neighbor_info.status[1]


class interfaces(object):
    def __init__(self, ip, user, pw, file):
        if not file:
            file = "interfaces.csv"
        self.ip = ip
        self.user = user
        self.pw = pw
        self.file = file  # nofile value will not save anyfile.
        self.status = ''
        self.result = ''
        run_header = ['Interface', 'State', 'Line Protocol', 'VLAN/Trunk', 'VLAN Name', 'Physical Address',
                      'Internet Address', 'Description', '(CDP)Neighbor Hostname ', '(CDP)Neighbor IP',
                      '(CDP)Neighbor interface', '(CDP)Neighbor Platform', '(CDP)Neighbor Capabilities',
                      '(CDP)Neighbor Version', '(LLDP)Neighbor Hostname', '(LLDP)Neighbor IP',
                      '(LLDP)Neighbor interface', '(LLDP)Neighbor Platform', '(LLDP)Neighbor Capabilities',
                      '(LLDP)Neighbor Version', 'MTU', 'BW', 'Reliability', 'Txload', 'Rxload', 'Media Type',
                      'Input flow-control', 'Output flow-control', 'Arp Timeout',
                      'Input Queue (size/max/drops/flushes)',
                      'Total Output Drops', 'Output Queue (size/max)', 'Input Rate', 'Output Rate']
        con = ssh(ip=self.ip, user=self.user, pw=self.pw, verbose=False)
        self.status = 'Connecting to : {}'.format(ip)
        con.connect()
        if con.status[0] > 0:
            self.status = 'Pulling data ...'
        inter_info = ciscoinfo(type='interfaces', ssh=con)
        cdp_info = ciscoinfo(type='cdp', ssh=con)
        lldp_info = ciscoinfo(type='lldp', ssh=con)
        for inter in range(0, len(inter_info.result)):
            item = inter_info.result[inter]
            for i in range(1, 13):
                item.insert(8, "")
            for cdpl in cdp_info.result:
                if item[0] == (cdpl[4].lower()):
                    item[8] = cdpl[0]
                    item[9] = cdpl[1]
                    item[10] = cdpl[5]
                    item[11] = cdpl[2]
                    item[12] = cdpl[3]
                    item[13] = cdpl[6]
            for llpdl in lldp_info.result:
                if item[0].lower().find(llpdl[4][:2].lower()) >= 0 and item[0].lower().find(
                        llpdl[4][2:].lower()) >= 0 and item[0].lower().find(llpdl[4][2:].lower()) + len(
                        llpdl[4][2:].lower()) == len(item[0]):
                    item[14] = llpdl[0]
                    item[15] = llpdl[1]
                    item[16] = llpdl[5]
                    item[17] = llpdl[2]
                    item[18] = llpdl[3]
                    item[19] = llpdl[6]
            inter_info.result[inter] = item
        self.result = inter_info.result
        if not self.file == 'nofile':
            save = savefile(self.file, self.result, run_header)
            self.file = save[1]
        self.status = ip + ' Result: ' + cdp_info.status[1]


def convertintf(interf_data):
    intf_list = []
    intf_list_2 = []
    intf_list_3 = []
    intf_item = []
    item_vlan = 0
    item_name = 0
    lz = [[', address is', 13, 14], ['internet address', 19, 20], ['description:', 13, 60], ['mtu', 4, 'bytes'],
          [', bw ', 5, 'kbit'], ['reliability', 11, ','], ['txload', 7, ','], ['rxload', 7, 15], ['media type', 14, 20],
          ['input flow-control is', 22, ','], ['output flow-control', 22, 30], ['arp timeout', 12, 10],
          ['input queue', 12, '('], ['total output drops', 19, 10], ['output queue', 13, '('],
          ['input rate', 11, 20], ['output rate', 12, 20]]
    lines = []
    for i in interf_data:
        lines.append(i.rstrip())
    sw_part = 1
    for i in range(0, len(lines)):
        l = lines[i].lower()
        if len(lines[i]) == 0 or l.find('show') > 0:  # remote empty lines and command lines
            continue
        if sw_part == 1:  # process the first command show cdp ne detail
            if l[0] in 'vtgfpl':  # Initials of every possible interfaces.
                if len(intf_item) > 0:
                    intf_list.append(intf_item)
                intf_item = []
                for intf_i in range(0, 29):  # add X amount of fields to the list
                    intf_item.append('')
                intf_item[0] = (l[0:l.find(' ')])  # interface name
                intf_item[1] = (l[l.find('is ') + 3:l.find(',')])  # Line state
                intf_item[2] = (l[l.find('protocol is') + 12:])  # Protocol state
            ycount = 0
            for y in lz:
                ycount += 1
                lx = l.find(y[0])
                if lx > 0:
                    lx = lx + y[1]
                    if 'int' in str(type(y[2])):
                        intf_len = y[2]
                    else:
                        intf_len = l[lx:].find(y[2])
                    intf_valuex = l[lx:lx + intf_len]
                    intf_item[ycount + 4] = intf_valuex
        if l.find('port') == 0 and l.find('name') > 0 and l.find('status') > 0 and l.find(
                'vlan') > 0:  # show vlan interface status
            # intf_list.append(intf_item)  # append the last interface
            item_vlan = l.find('vlan')
            sw_part = 2
            continue
        if l.find('vlan') == 0 and l.find('name') > 0:  # show vlan command
            item_name = l.find('name')
            sw_part = 3
            continue
        if sw_part == 2:  # process the second command show interface status
            intf_item_aux = ['', '']
            intf_item_aux[0] = l[0:l.find(' ')]
            intf_item_aux[1] = l[item_vlan:item_vlan + l[item_vlan:].find(' ')]
            intf_list_2.append(intf_item_aux)
        elif sw_part == 3:  # process the 3rd  command show vlan
            intf_item_aux = ['', '']
            intf_item_aux[0] = l[0:l.find(' ')]
            intf_item_aux[1] = l[item_name:item_name + l[item_name:].find(' ')]
            intf_list_3.append(intf_item_aux)
    for i in range(0, len(intf_list)):
        item = intf_list[i]
        for y in range(0, len(intf_list_2)):  # Merges "show interfaces" and "show interfaces status" commands
            item_2 = intf_list_2[y]
            if item_2[0][0:2] == item[0][0:2] and item[0][find_first_number(item[0]):] == item_2[0][2:]:
                intf_list[i][3] = item_2[1]
                break
        item = intf_list[i]
        for y in range(0, len(intf_list_3)):  # Merges "show interfaces" and "show vlan" commands
            item_3 = intf_list_3[y]
            if item_3[0] == item[3]:
                item[4] = item_3[1]
                intf_list[i] = item
                break
    for y in range(0, len(intf_list)):
        if len(intf_list[y]) == 0:
            intf_list.remove[y]
    return intf_list


def convertcdp(cdp_data):
    cdp_lines = []
    cdp_result = []
    cdp_device = cdp_ip = cdp_platform = cdp_capabilities = cdp_interface1 = cdp_interface2 = cdp_version = ''
    for i in cdp_data:
        cdp_lines.append(i.rstrip())
    for i in range(0, len(cdp_lines) - 1):
        # if not len(cdp_lines[i]) > 0:
        #     continue
        y = cdp_lines[i]
        z = ''
        if i > 0:
            z = cdp_lines[i + 1]
        if ("--------" in y and i > 0) or i == len(cdp_lines) - 2:
            cdp_item = [cdp_device, cdp_ip, cdp_platform, cdp_capabilities, cdp_interface1, cdp_interface2,
                        cdp_version]
            if len(cdp_device) > 0:
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


def convertlldp(lldp_data):
    lldp_lines = []
    lldp_result = []
    lldp_device = lldp_ip = lldp_platform = lldp_capabilities = lldp_interface1 = lldp_interface2 = lldp_version = ''
    #print(lldp_data)
    for i in lldp_data:
        lldp_lines.append(i.rstrip())
    for i in range(0, len(lldp_lines) - 1):
        y = lldp_lines[i]
        z = ''
        if i > 0:
            z = lldp_lines[i + 1]
        if ("--------" in y and i > 0) or i == len(lldp_lines) - 2:
            lldp_item = [lldp_device, lldp_ip, lldp_platform, lldp_capabilities, lldp_interface1, lldp_interface2,
                         lldp_version]
            if len(lldp_device) > 0:
                lldp_result.append(lldp_item)
        if "--------" in y:
            lldp_device = lldp_ip = lldp_platform = lldp_capabilities = lldp_interface1 = lldp_interface2 = lldp_version = ''
            lldp_item = []
        if "system name" in y.lower():
            lldp_device = (y[13:])
        if "ip:" in y.lower():
            lldp_ip = (y[8:])
        if "system capabilities" in y.lower():
            lldp_platform = (y[21:])
        if "enabled capabilities" in y.lower():
            lldp_capabilities = (y[22:])
        if "local intf: " in y.lower():
            lldp_interface1 = (y[12:])
        if "port id: " in y.lower():
            lldp_interface2 = (y[9:])
        if "system description" in y.lower():
            lldp_version = z
    return lldp_result


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


def savefile(fn1, lines_list, headers_list):
    header = ''
    fn2 = fn1[0:fn1.rfind('.')] + '_' + datetime.now().strftime('%Y%m%d_%H%M%S') + fn1[fn1.rfind('.'):]
    for i in range(0, len(headers_list)):
        header = header + '"' + headers_list[i] + '"'
        if i != len(headers_list) - 1:
            header = header + ","
    header = header + '\n'
    if path.exists(fn1):
        fn1 = fn2
    try:
        file1 = open(fn1, "w")
    except Exception as e:
        return [False, e]
    file1.writelines(header)
    for i in range(0, len(lines_list)):
        line = ''
        for y in range(0, len(lines_list[i])):
            line = line + '"' + lines_list[i][y] + '"'
            if y != len(lines_list[i]) - 1:
                line = line + ','
        line = line + '\n'
        file1.writelines(line)
    file1.close()
    # return [True, "File Saved!!!"]
    return [True, fn1]


def streamtolines(stream):
    lines = []
    line = ''
    for letter in stream:
        if letter == 13:
            next
        if letter == 10:
            if not ('show' in line or 'terminal length' in line):  # remove lines with commands from output.
                lines.append(line)
            line = ''
        else:
            line = line + chr(letter)
    return lines


def find_first_number(text_string):
    text_find = '0123456789'
    letter_index = 0
    find_switch = False
    for letter in text_string:
        if letter in text_find:
            find_switch = True
            break
        letter_index = letter_index + 1
    if not find_switch:
        letter_index = -1
    return letter_index


def ip_list(ips):  # Validate and Convert IPs into a str list of individual IPs.
    ips_end_list = []
    ips_sum_list = set()
    for i in ips.split(','):
        x = i.split('-')
        try:
            ips_sum_list.update(
                ipaddress.summarize_address_range(ipaddress.ip_address(x[0]), ipaddress.ip_address(x[-1])))
        except ValueError as e:
            return []  # IP validation. return an empty list if one ip address is incorrect.
    ips_sum_list = sorted(ips_sum_list)
    for i in ips_sum_list:
        for y in i:
            ips_end_list.append(str(y))
    return ips_end_list


def check_args(args):
    # Returns
    #           [0] Boolean.    True        : Arguments are right, False: Missing or wrong  arguments.
    #           [1] String.     cdp         : Cisco discovery protocol report.
    #                           interfaces  : Interfaces report.
    #                           access      : Try access to the device
    #           [2] String.     IPs         : IP list.
    #           [3] String.     user        : User that will be used to  login into devices.
    #
    #

    ar_type = ar_ip = ar_user = ar_pass = ''
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
        if '-p:' in y:
            ar_pass = (args[i][args[i].find("-p:") + 3:])
    if len(ar_ip) == 0 or ar_type not in ['cdp', 'lldp', 'interfaces', 'access']:
        arg_sw = False
    else:
        arg_sw = True
    return [arg_sw, ar_type, ar_ip, ar_user, ar_pass]


def printarg():

    print()
    print('Pull data from Cisco Devices and return a formatted file.')
    print()
    print("ci.py -t:'cdp'|'interfaces' -ip:192.168.1.1 [-u:user]")
    print()
    print('-t   Requested info')
    print('         -t:cdp')
    print('         -t:lldp')
    print('         -t:interfaces')
    print('         -t:access')
    print('-ip  IP of the Cisco device')
    print('-u   User to log in ')


def pull_data(ctype, ip, user, pw, verbose):
    filename = ctype + "_" + ip + ".csv"
    cdp_info = ciscoinfo
    print('Processing IP:', ip)
    if ctype == "interfaces":
        cdp_info = interfaces(ip=ip, user=user, pw=pw, file=filename)
    elif ctype == "cdp":
        cdp_info = neighbor(proto="cdp", ip=ip, user=user, pw=pw, file=filename)
    if ctype == "lldp":
        cdp_info = neighbor(proto="lldp", ip=ip, user=user, pw=pw, file=filename)
    print('Done IP:', ip, cdp_info.status)


def main(argvs):
    chk_arg = check_args(argvs)
    #    if not chk_arg[5]:
    #        chk_arg[5] = '.csv'
    if not chk_arg[0]:
        exit()
    if len(chk_arg[3]) == 0:
        chk_arg[3] = getpass.getuser()
    if len(chk_arg[4]) == 0:
        chk_arg[4] = getpass.getpass()
    main_type = chk_arg[1]
    main_ip = chk_arg[2]
    main_user = chk_arg[3]
    main_pw = chk_arg[4]
    jobs = []
    if main_type == 'access':
        main_access = ciscopass(main_ip, main_user, main_pw)
        print()
        print('Access found:')
        print(main_access.status)

    if main_type in ['cdp', 'lldp', 'interfaces']:
        for i in main_ip:
            multicon = multiprocessing.Process(target=pull_data,
                                               args=(main_type, i, main_user, main_pw, True,))
            jobs.append(multicon)
            multicon.start()


if __name__ == "__main__":
    main(sys.argv)
