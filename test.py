from ciscoinfo import streamtolines, convertintf
import pprint
import test2

result = convertintf('')
for i in result:
    print(i)
#
# intf_item = []
#
# lz = [[', address is', 13, 14], ['description:', 13, 60], ['mtu', 4, 'bytes'], [', bw ', 5, 'kbit'],
#       ['reliability', 11, ','], ['txload', 7, ','], ['media type', 14, 20]]
# data2 = streamtolines(test2.data)
# lines = []
# intf_list = []
# for i in data2:
#     lines.append(i.rstrip())
# pprint.pprint(lines)
#
# for i in range(0, len(lines) - 1):
#     if len(lines[i]) == 0:
#         continue
#     l = lines[i].lower()
#     if lines[i][0] != ' ':
#         # intf_item = [intf_name, intf_state, intf_protocol, intf_address, intf_description, intf_mtu]
#         intf_list.append(intf_item)
#         # intf_name = intf_state = intf_protocol = intf_address = intf_description = intf_mtu = ''
#         intf_item = []
#         for intf_i in range(0, 20):
#             intf_item.append('')
#         # intf_name = l[0:l.find(' ')]
#         # intf_state = l[l.find('is ') + 3:l.find(',')]
#         # intf_protocol = l[l.find('protocol is') + 12:]
#         intf_item[0] = (l[0:l.find(' ')])  # interface name
#         intf_item[1] = (l[l.find('is ') + 3:l.find(',')])  # Line state
#         intf_item[2] = (l[l.find('protocol is') + 12:])  # Protocol state
#     ycount = 0
#     for y in lz:
#         print(y)
#         ycount += 1
#         lx = l.find(y[0])
#         if lx > 0:
#             lx = lx + y[1]
#             if 'int' in str(type(y[2])):
#                 intf_len = y[2]
#             else:
#                 intf_len = l[lx:].find(y[2])
#             intf_valuex = l[lx:lx + intf_len]
#             intf_item[ycount + 3] = intf_valuex
#             print('{} {} {}'.format(y, lx, intf_valuex))
# for i in intf_list:
#     print(i)
