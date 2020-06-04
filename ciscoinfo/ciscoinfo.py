# Aleandro Andrea aaah1976@gmail.com
# 05/2020
#
# ciscoinfo
#       Arguments:
#           cisco_type: String. cdp, interfaces
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
# cdp.  does not save anyfile.
#       Arguments:
#           ip      : String. Device's IP
#           user    : String. User to login.
#           pw      : String. Password to login
#       Returns:
#           object.status = list with status
#           object.result = list with cdp info
#
# interfaces.   does not save anyfile.
#       Arguments:
#           ip      : String. Device's IP
#           user    : String. User to login.
#           pw      : String. Password to login
#       Returns:
#           object.status = list with status
#           object.result = list with interfaces info


import time
import paramiko
from datetime import datetime
from os import path
import ipaddress
import multiprocessing


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
            #
        try:
            self.socket.connect(self.ip, port=22, username=self.user, password=self.pw)
        except paramiko.ssh_exception.AuthenticationException:
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

    def readssh(self):
        output = b''
        nonewdatacount = 0
        while True:
            time.sleep(1)
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
    def __init__(self, ip: str, user: str, pw: str, ):
        # Parameters ip, user and pw.
        #              ip:      String. List of valid IPs addresses
        #              user:    String. List of Usernames used to connect. Comma separated.
        #              pw:      String. List of Passwords used to connect. Comma separated.
        ip = ip_list(ip)
        user = user.split(',')
        pw = pw.split(',')
        if len(ip) == 0 or len(user) == 0 or len(pw) == 0:
            return
        index_worker = 0
        for ip_worker in ip:
            for user_worker in user:
                for pw_worker in pw:
                    index_worker = index_worker + 1


class ciscoinfo(object):
    def __init__(self, type, ssh: ssh, file):
        # parameters cisco_type, cisco_ssh, cisco_file
        #
        # cisco_type    Information that will be pulled
        #   Values:
        #               'cdp'             cdp report
        #               'interfaces'      interfaces report
        #
        # ssh Object    SSH object with an active connection to an end-point
        # cisco_file     file name where results will be saved.
        if len(file) == 0:
            if 'interfaces' in type:
                cisco_file = 'interfaces.csv'
            if 'cdp' in type:
                cisco_file = 'cdp.csv'

        self.type = type
        self.ssh = ssh
        self.data = []
        self.status = [-1, 'Unknown Issue']
        self.file = file
        self.result = ""
        self.run()

    def run(self):
        run_command = ''
        run_header = ''
        if self.ssh.status[0] > 0:
            # Commands and Headers to save files
            if self.type == 'cdp':
                run_command = 'show cdp nei detail'
                run_header = ['Hostname', 'IP', 'Platform', 'Capabilities', 'Local Interface', 'Remote Interface',
                              'Version']
            if self.type == 'interfaces':
                run_command = 'show interfaces\n show interfaces status\n show vlan'
                run_header = ['Interface', 'State', 'Line Protocol', 'VLAN/Trunk', 'VLAN Name', 'Physical Address',
                              'Internet Address', 'Description', 'MTU', 'BW', 'Reliability', 'Txload', 'Rxload',
                              'Media Type', 'Input flow-control', 'Output flow-control', 'Arp Timeout',
                              'Input Queue (size/max/drops/flushes)', 'Total Output Drops', 'Output Queue (size/max)',
                              'Input Rate', 'Output Rate']
            # Commands and Headers to save files ######################################
            self.result = self.ssh.execute(run_command)
            self.status = [0, 'Pulling Data ...']
            if self.type == 'cdp':
                self.result = convertcdp(self.result)
            if self.type == 'interfaces':
                self.result = convertintf(self.result)
            self.status = [1, 'Pulled {} Lines.'.format(len(self.result))]
            if not self.file == 'nofile':
                save = savefile(self.file, self.result, run_header)
                if self.ssh.verbose:
                    print(save)
                if not save[0]:
                    exit()
            self.status[1] = self.status[1] + '.'
        else:
            self.status = [-1, self.ssh.status[1]]


class cdp(object):
    def __init__(self, ip, user, pw):
        self.ip = ip
        self.user = user
        self.pw = pw
        self.status = ''
        self.result = ''
        cdp_info = ciscoinfo
        con = ssh(ip=self.ip, user=self.user, pw=self.pw, verbose=False)
        self.status = 'Connecting to : {}'.format(ip)
        con.connect()
        if con.status[0] > 0:
            self.status = 'Pulling data ...'
        cdp_info = ciscoinfo(type='cdp', ssh=con, file='nofile')
        self.result = cdp_info.result
        self.status = ip + ' Result: ' + cdp_info.status[1]


class interfaces(object):
    def __init__(self, ip, user, pw):
        self.ip = ip
        self.user = user
        self.pw = pw
        self.status = ''
        self.result = ''
        con = ssh(ip=self.ip, user=self.user, pw=self.pw, verbose=False)
        self.status = 'Connecting to : {}'.format(ip)
        con.connect()
        if con.status[0] > 0:
            self.status = 'Pulling data ...'
        cdp_info = ciscoinfo(type='interfaces', ssh=con, file='nofile')
        self.result = cdp_info.result
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
            if l[0] in 'vtgfpl':
                if len(intf_item) > 0:
                    intf_list.append(intf_item)
                intf_item = []
                for intf_i in range(0, 22):  # add X amount of fields to the list
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
    return [True, "File Saved!!!"]


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
