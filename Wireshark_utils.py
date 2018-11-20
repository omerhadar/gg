import sys
from io import StringIO


def get_show_data(packet):
    return packet.show(dump=True).splitlines()


def get_hex_data(packet, func):
    s = func(packet, dump=True)
    lst = ["", "", ""]
    for line in s.splitlines():
        lst[0] += line[0:4] + "\n"
        lst[1] += line[6:38] + "\n"
        lst[2] += line[39:56] + "\n"
    return lst
