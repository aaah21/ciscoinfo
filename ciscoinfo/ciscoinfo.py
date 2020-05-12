# Aleandro Andrea aaah1976@gmail.com
# 05/2020
#

import time
import paramiko
from datetime import datetime
from os import path
import pprint


class ssh(object):
    def __init__(self, ip, user, pw):
        self.ip = ip
        self.user = user
        self.pw = pw
        self.ssh_status = ['', '']
        self.ssh_socket = paramiko.SSHClient()
        self.ssh_socket.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.channel = ''

    def connect(self):
        try:
            self.ssh_socket.connect(self.ip, port=22, username=self.user, password=self.pw)
        except paramiko.ssh_exception.AuthenticationException:
            self.ssh_status = [-2, 'SSH Connection. Failed Authentication']
            return
        except:
            self.ssh_status = [-1, 'SSH Host does not respond']
            return
        self.channel = self.ssh_socket.invoke_shell()
        chda = ''
        # host = str()
        # srcfile = str()
        while True:
            if self.channel.recv_ready():
                chda = str(self.channel.recv(9999))
            else:
                continue
            chda = str(chda)
            if chda.find('>') > 0:
                self.ssh_status = [1, 'SSH User Mode']
                return
            elif chda.find('#') > 0 and chda.find(')#') < 0:
                self.ssh_status = [1, 'SSH Privilege Mode']
                return
                break

    def execute(self, command):
        output = b''
        command = 'terminal length 0 \n' + command
        self.channel.send(command)
        time.sleep(2)
        output2 = self.channel.recv(len(command) + 100)
        self.channel.send('\n')
        time.sleep(2)
        while self.channel.recv_ready():
            output = output + self.channel.recv(65535)
            time.sleep(2)
        output = streamtolines(output)
        return output


class cdp(object):
    def __init__(self, cdp_ssh: ssh, cdp_file):
        if len(cdp_file) == 0:
            cdp_file = 'cdp.txt'
        self.cdp_ssh = cdp_ssh
        self.cdp_data = []
        self.cdp_status = [-1, 'Unknown Issue']
        self.cdp_file = cdp_file
        self.run()

    def run(self):
        if self.cdp_ssh.ssh_status[0] > 0:
            cdp_result = self.cdp_ssh.execute('show cdp nei detail')
            self.cdp_status = [0, 'Pulling Data ...']
            cdp_result = convertcdp(cdp_result)
            self.cdp_status = [1, 'Pulled {} Devices.'.format(len(cdp_result))]
            cdp_save = savefile(self.cdp_file, cdp_result,
                                ['Hostname', 'IP', 'Platform', 'Capabilities', 'Local Interface',
                                 'Remote Interface', 'Version'])
            self.cdp_status[1] = self.cdp_status[1] + '\n' + cdp_save[1]
            if not cdp_save[0]:
                exit()
        else:
            self.cdp_status = [-1, self.cdp_ssh.ssh_status[1]]


class ciscoinfo(object):
    def __init__(self, cisco_type, cisco_ssh: ssh, cisco_file):
        # cisco_type Values
        # 'cdp'             cdp report
        # 'interfaces'      interfaces report
        if len(cisco_file) == 0:
            cisco_file = 'interfaces.txt'
        self.cisco_ssh = cisco_ssh
        self.cisco_data = []
        self.cisco_status = [-1, 'Unknown Issue']
        self.cisco_file = cisco_file
        self.cisco_type = cisco_type
        self.run()

    def run(self):
        run_command = ''
        run_header = ''
        if self.cisco_ssh.ssh_status[0] > 0:
            if self.cisco_type == 'cdp':
                run_command = 'show cdp nei detail'
                run_header = ['Hostname', 'IP', 'Platform', 'Capabilities', 'Local Interface', 'Remote Interface',
                              'Version']
            if self.cisco_type == 'interfaces':
                run_command = 'show interfaces'
                run_header = ['Interface', 'State', 'Line Protocol', 'Physical Address', 'Internet Address',
                              'Description', 'MTU', 'BW', 'Reliability', 'Txload', 'Rxload', 'Media Type',
                              'Input flow-control', 'Output flow-control', 'Arp Timeout',
                              'Input Queue (size/max/drops/flushes)',
                              'Total Output Drops', 'Output Queue (size/max)', 'Input Rate', 'Output Rate']
            cisco_result = self.cisco_ssh.execute(run_command)
            self.cisco_status = [0, 'Pulling Data ...']

            if self.cisco_type == 'cdp':
                cisco_result = convertcdp(cisco_result)
            if self.cisco_type == 'interfaces':
                cisco_result = convertintf(cisco_result)

            self.cisco_status = [1, 'Pulled {} Lines.'.format(len(cisco_result))]
            cisco_save = savefile(self.cisco_file, cisco_result, run_header)
            self.cisco_status[1] = self.cisco_status[1] + '\n' + cisco_save[1]
            if not cisco_save[0]:
                exit()
        else:
            self.cisco_status = [-1, self.cisco_ssh.ssh_status[1]]


def convertintf(interf_data):
    intf_item = []
    lz = [[', address is', 13, 14], ['internet address', 19, 20], ['description:', 13, 60], ['mtu', 4, 'bytes'],
          [', bw ', 5, 'kbit'], ['reliability', 11, ','], ['txload', 7, ','], ['rxload', 7, 15], ['media type', 14, 20],
          ['input flow-control is', 22, ','], ['output flow-control', 22, 30], ['arp timeout', 12, 10],
          ['input queue', 12, '('], ['total output drops', 19, 10], ['output queue', 13, '('],
          ['input rate', 11, 20], ['output rate', 12, 20]]
    lines = []
    intf_list = []
    for i in interf_data:
        lines.append(i.rstrip())
    for i in range(0, len(lines) - 1):
        if len(lines[i]) == 0:
            continue
        l = lines[i].lower()
        if lines[i][0] != ' ':
            if len(intf_item) > 0:
                intf_list.append(intf_item)
            intf_item = []
            for intf_i in range(0, 20):
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
                intf_item[ycount + 2] = intf_valuex
    return intf_list


def convertcdp(cdp_data):
    cdp_lines = []
    cdp_result = []
    cdp_device = cdp_ip = cdp_platform = cdp_capabilities = cdp_interface1 = cdp_interface2 = cdp_version = ''
    for i in cdp_data:
        cdp_lines.append(i.rstrip())
    for i in range(0, len(cdp_lines) - 1):
        if not len(cdp_lines[i]) > 0:
            continue
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
    fn2 = fn1[0:fn1.rfind('.')] + '_' + datetime.now().strftime('%Y%m%d_%H%M%S') + fn1[fn1.rfind('.') - 1:]
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


def streamtolines(stream):
    lines = []
    line = ''
    for letter in stream:
        if letter == 13:
            next
        if letter == 10:
            lines.append(line)
            line = ''
        else:
            line = line + chr(letter)
    return lines
