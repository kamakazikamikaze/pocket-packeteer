from __future__ import print_function
from scapy import *
from . import scanner

DEFAULT_PORTS = [port for port in range(1, 4096)]


# scapy.plist.SndRcvList
# __init__(self, res=None, name='Results', stats=None)

def scan(target, proto, ports=None, timeout=10, **kwargs):
    r'''
    Scan a range of ports on the target

    :param str target: IP address or FQDN of target
    :param proto: Transport protocol to use
    :type proto: ICMP or TCP or UDP
    :param ports: All ports to scan
    :type ports: iterable(int or str)
    :param kwargs: Keyword arguments to pass to ``scapy.sendrecv.sr1``
    :return: Responses
    :rtype: scapy.plist.SndRcvList
    '''
    if timeout <= 0:
        timeout = 10
    ip = IP(dst=target)
    response = []
    for port in ports:
        response.append(
            (port, sr1(ip / proto(dport=port), timeout=timeout, **kwargs))
        )
    return response


def scanICMP(targets, timeout=10, **kwargs):
    r'''
    Ping one or more target(s)

    :param targets: IP address(es) or FQDN of target(es)
    :type targets: str or iterable(str)
    :param kwargs: Keyword arguments to pass to ``scapy.sendrecv.sr1``
    :return: Ping results
    :rtype: tuple(list(str), list(str), list(scapy.layers.inet.IP))
    '''
    if timeout <= 0:
        timeout = 10
    if isinstance(targets, str):
        targets = (targets, )
    alive = []
    dead = []
    responses = []
    for target in targets:
        responses.append(sr1(IP(dst=target) / ICMP(),
                             timeout=timeout, **kwargs))
        if not responses[-1]:
            dead.append(target)
        else:
            alive.append(target)
    return alive, dead, responses


def scanUDP(target, ports=None, timeout=10, **kwargs):
    r'''
    Scan a range of ports on the target using UDP

    :param str target: IP address or FQDN of target
    :param ports: All ports to scan
    :type ports: iterable(int or str)
    :return: Results
    :rtype: list(scapy.layers.inet.IP)
    '''
    if timeout <= 0:
        timeout = 10
    answered, unanswered = scan(target, UDP, ports, timeout, **kwargs)
    # TODO: Implement a proper logger
    if not answered:
        print('No ICMP responses were received; cannot verify if target is up')
    return unanswered


def scanTCP(target, ports=None, timeout=10, **kwargs):
    r'''
    Scan a range of ports on the target using UDP

    :param str target: IP address or FQDN of target
    :param ports: All ports to scan
    :type ports: iterable(int or str)
    :return: Results
    :rtype: scapy.plist.SndRcvList
    '''
    if timeout <= 0:
        timeout = 10
    return scan(target, TCP, ports, timeout, **kwargs)[0]


def scanSYN(target, ports=None, timeout=10, **kwargs):
    r'''
    Scan a range of ports on the target using UDP

    :param str target: IP address or FQDN of target
    :param ports: All ports to scan
    :type ports: iterable(int or str)
    :return: Results
    :rtype: list(scapy.layers.inet.IP)
    '''
    if timeout <= 0:
        timeout = 10
    ip = IP(dst=target)
    results = []
    for port in ports:
        response = sr1(ip / TCP(dport=port, flags='S'))
        if response and response.flags == 0x14:
            results.append(response)
            send(ip / TCP(dport=port, flags='R'))
    return results
