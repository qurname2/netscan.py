#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Netscan one host or network range"""

import ipaddress
import sys
import socket
import multiprocessing
from datetime import datetime
import tempfile
import os


def host_or_network():
    """
    find out what user entered
    :return: ipv4 or network or error
    """
    try:
        return ipaddress.IPv4Address(sys.argv[1])
    except ipaddress.AddressValueError:
        try:
            return ipaddress.ip_network(sys.argv[1])
        except ValueError:
            return 'Upss..You are wrong, input without ' \
                   'bit host, example: 192.168.20.0/24'


def worker(host_ip, port, temp_dir, flag):
    """
    Main worker function
    :param host_ip: ip address target
    :param port: port target
    :param temp_dir: temp_dir on your host
    :param flag: it is first check or not?
    """
    temp_file = temp_dir + f'/{host_ip}'
    delay = 0.1
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(delay)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        result = sock.connect_ex((host_ip, port))
        if result == 0:
            res = f"Host: {host_ip}    Port {port}: Open/tcp"
            if flag:
                with open(temp_file + '.v-2', 'a') as f:
                    f.write(res + '\n')
            else:
                write_to_temp_file(host_ip, res + '\n', temp_dir)
                print(res)
        sock.close()
    except socket.error:
        print("Couldn't connect to server")
        exit(1)


def what_print(host_ip, temp_dir):
    """
    Compares 2 files and decides what to print
    :param host_ip: ip address target
    :param temp_dir: temp_dir on your host
    """
    with open(temp_dir + f'/{host_ip}', 'r') as f:
        data1 = f.read()
    set_data1 = {i for i in data1.split('\n') if i}
    with open(temp_dir + f'/{host_ip}.v-2') as f2:
        data2 = f2.read()
    set_data2 = {x for x in data2.split('\n') if x}
    if bool(set_data1 ^ set_data2):
        print(data2)
    else:
        print(f'Target - {host_ip}: No new records found in the last scan.')


def scan_ports(host_ip):
    """
    Port scan on the received address
    :param host_ip:
    :return:
    """
    t1 = datetime.now()
    start_port = 1
    end_port = 1024
    temp_dir = tempfile.gettempdir()
    try:
        flag = True if os.path.isfile(temp_dir + f'/{host_ip}') else False
        for port in range(start_port, end_port):
            t = multiprocessing.Process(target=worker, args=(host_ip, port, temp_dir, flag))
            t.start()
        if flag:
            what_print(host_ip, temp_dir)

    except KeyboardInterrupt:
        print("You pressed Ctrl+C")
        exit(1)
    finally:
        t2 = datetime.now()
        print(f'Total time for {host_ip}%s' % (t2 - t1))
        if os.path.isfile(temp_dir + f'/{host_ip}.v-2'):
            os.remove(temp_dir + f'/{host_ip}.v-2')


def write_to_temp_file(host_ip, data_to_write, temp_dir):
    """
    Write result to temp_file on your OS
    :param host_ip:
    :param data_to_write:
    :return:
    """
    temp_file_source = temp_dir + f'/{host_ip}'
    if os.path.isfile(temp_file_source):
        with open(temp_file_source, 'a') as f:
            f.write(str(data_to_write))
    else:
        with open(temp_file_source, 'w') as f:
            f.write(str(data_to_write))


def main():
    """
    Main function
    :return:
    """
    host = host_or_network()
    if isinstance(host, str):
        print(host)
        exit(1)
    else:
        if isinstance(host, ipaddress.IPv4Address):
            print("-" * 60 + f"\nPlease wait, scanning remote host {str(host)}\n" +
                  "-" * 60)
            scan_ports(str(host))
        else:
            for host in host.hosts():
                scan_ports(str(host))


if __name__ == "__main__":
    main()
