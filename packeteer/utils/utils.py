from scapy.all import *
# from scapy.utils import ltoa
# import sqlite3

try:
    input = raw_input
except NameError:
    pass


def ltcidr(mask_as_long):
    r'''
    Convert a network mask into a CIDR

    :param
    '''
    return sum([bin(int(x)).count("1") for x in ltoa(mask_as_long).split(".")])


def get_default_iface():
    r'''
    Get the default interface for the current host

    :rtype: str
    '''
    return conf.iface


def get_default_route():
    r'''
    Get the default route and subnet mask for the current device

    :rtype: tuple(long, long)
    '''
    route = None
    for route in conf.route.routes:
        if route[3] != get_default_iface():
            continue
        elif route[0] == 0:
            continue
        elif ltoa(route[0]).split('.')[-1] != '0':
            continue
        else:
            return route[0], route[1]
    raise Exception(
        'No acceptable route found! Do you have your IP configured?')


def scan_tcp(dst='192.168.1.1', retries=2,
             msg='New phone, who dis?', timeout=2):
    r'''
    '''
    ans, unans = sr(IP(dst=dst, proto=(0, 255)) / msg,
                    retry=retries, timeout=timeout)


def query_mdns(qname, timeout=2):
    r'''
    '''
    return sr1(IP(dst='224.0.0.251') / UDP(dport=5353) /
               DNS(qd=DNSQR(qtype='PTR', qname=qname)), timeout=timeout)


def check_snmp(target, oid='1.3.6.1.2.1.1.1.0',
               community='public', retries=1, timeout=2):
    packet = SNMP(
        version=2,
        community=community,
        PDU=SNMPget(
            varbindlist=[
                SNMPvarbind(
                    oid=oid)]))
    sr1(IP(dst=target) / UDP() / packet, retry=retries, timeout=timeout)


def scan_arp(route=None, netmask=None, iface=None, timeout=2):
    r'''
    Scan local network using ARP

    :param route: Network to scan
    :type route: long or string
    :param netmask: Subnet mask
    :type route: long or string
    :param str iface: Network interface to use (if not default)
    :param int timeout: Time to wait for ARP responsess
    :return: Answered and unanswered summaries
    :rtype: tuple(scapy.layers.l2.ARPingResult, scapy.layers.l2.ARPingResult)
    '''
    # return arping('.'.join(ip_gate[0:ip_gate.index('0')]) + '.*')
    if not route:
        route = ltoa(get_default_route()[0])
    elif isinstance(route, long):
        route = ltoa(route)
    elif isinstance(route, str):
        pass
    else:
        raise TypeError('Route is an invalid type!')

    if not netmask:
        netmask = str(ltcidr(get_default_route()[1]))
    elif isinstance(route, long):
        netmask = str(ltcidr(netmask))
    elif isinstance(netmask, str):
        try:
            if 0 <= int(netmask) < 32:
                pass
        except ValueError:
            netmask = str(ltcidr(atol(netmask)))
    elif isinstance(netmask, int):
        if 0 <= int(netmask) < 32:
            netmask = str(netmask)
        else:
            raise ValueError('Netmask passed as CIDR but is invalid!')
    else:
        raise TypeError('Route is an invalid type!')

    return srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
               ARP(pdst=route + '/' + netmask), iface, timeout=timeout)

if __name__ == '__main__':
    ans, unans = scan_arp()
    ans.show()
    input('Press any key to continue...')
    unans.show()
