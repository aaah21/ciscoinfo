import time
import paramiko
import pprint


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
        self.channel.recv(len(command))
        self.channel.send('\n')
        time.sleep(2)
        while self.channel.recv_ready():
            output = output + self.channel.recv(65535)
            time.sleep(2)
        output = streamtolines(output)
        return output
