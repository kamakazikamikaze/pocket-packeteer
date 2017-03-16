from __future__ import print_function
from collections import defaultdict
from netaddr import iter_iprange, IPNetwork
from os import pathsep
from os.path import abspath
# from scapy import *
# from scapy.sendrecv import send, sr1
# from scapy.layers.inet import IP, TCP, UDP, ICMP
# from scapy.plist import SndRcvList
from scapy.all import *
from sys import exit
from functools import reduce

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
    :rtype: list(tuple(port, scapy.plist.SndRcvList))
    '''
    if timeout <= 0:
        timeout = 10
    ip = IP(dst=target)
    responses = []
    for port in ports:
        responses.append(
            (port, sr1(ip / proto(dport=port), timeout=timeout, **kwargs))
        )
    return responses


def scanICMP(targets, timeout=10, **kwargs):
    r'''
    Ping one or more target(s)

    :param targets: IP address(es) or FQDN of target(es)
    :type targets: str or iterable(str)
    :param kwargs: Keyword arguments to pass to ``scapy.sendrecv.sr1``
    :return: Ping results
    :rtype: tuple(list(str), list(scapy.layers.inet.IP))
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
    # We'll allow the dead to be returned
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
    responses = scan(target, UDP, ports, timeout, **kwargs)
    # TODO: Implement a proper logger
    answered = filter(lambda r: r[1] is not None, responses)
    unanswered = filter(lambda r: r[1] is None, responses)
    if not answered:
        print(
            'No ICMP responses were received for',
            target,
            'in UDP scan. Cannot verify if target is up')
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
    return filter(lambda r: r[1] is not None, scan(
        target, TCP, ports, timeout, **kwargs))


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
        response = sr1(ip / TCP(dport=port, flags='S'),
                       timeout=timeout, **kwargs)
        # If we're received a SYN+ACK, save the result for later
        if response and response[TCP].flags == 'SA':
            results.append((port, response))
            send(ip / TCP(dport=port, flags='R'), **kwargs)
    return results


def parse_targets(targets):
    r'''
    Expand the parameter into individual IP addresses

    .. todo:: Make this recursive. Too hungry right now to think

    :param targets: IP address(es) of host to target
    '''
    targets = [targets] if isinstance(targets, str) else targets
    temptargets = []
    for target in targets:
        # Filter blanks
        temptargets.extend(
            filter(
                lambda x: x is not '',
                target.strip().split(',')))
    targets = temptargets
    temptargets = []
    for target in targets:
        if '/' in target:
            temptargets.extend(list(map(str, IPNetwork(target))))
        elif '-' in target:
            start, end = target.split('-')
            temptargets.extend(list(map(str, iter_iprange(start, end))))
        else:
            temptargets.append(target)
    return temptargets


def parse_ports(ports):
    r'''
    Expand the parameter into a list of individual ports

    :param ports: All ports to scan
    :type ports: str or int or list(str or int)
    :rtype: list(int)
    '''
    ports = [ports] if isinstance(ports, str) else ports
    tempports = []
    for port_range in ports:
        tempports.extend(
            filter(
                lambda x: x is not '',
                port_range.strip().split(',')))
    ports = tempports
    tempports = []
    for port_range in ports:
        if isinstance(port_range, int):
            tempports.append(port_range)
        elif '-' in port_range:
            start, end = port_range.split('-')
            tempports.extend(range(int(start), int(end) + 1))
        else:
            tempports.append(int(port_range))
    return tempports

scan_actions = {
    'icmp': scanICMP,
    'udp': scanUDP,
    'tcp': scanTCP,
    'syn': scanSYN
}

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description=(
            'Assignment 3 deliverable. A full Scanner class with '
            'multiprocessing capability will be created later. This '
            'invocation is to help you get started. Specify targets in the '
            'CLI or in a file with a list of hosts or both.'))
    parser.add_argument('-i', '--input-file',
                        help=('File containing hosts. One per line. CIDR and '
                              'ranges are accepted'))
    parser.add_argument('-t', '--targets', nargs='+',
                        help=(
                            'Targets to ping. A range or CIDR is allowed. '
                            'Specify multiple hosts by delimiting with spaces '
                            'or commas or some (evil) mixture thereof. Ex: '
                            '10.0.0.3-10.0.1.252,10.1.1.1 10.4.4.1-10.4.4.2'))
    parser.add_argument(
        '--transport',
        choices=[
            'tcp',
            'udp',
            'icmp',
            'syn'],
        default=['tcp'],
        nargs='+')
    parser.add_argument(
        '-p',
        '--ports',
        nargs='+',
        help=('Ports to scan. Specify as many as desired. Multiple ranges '
              'are accepted. Mix them up as desired. Please delimit them '
              'with commas and/or whitespace.'),
        default=DEFAULT_PORTS)
    parser.add_argument(
        '-r',
        '--report',
        choices=[
            'pdf',
            'csv'],
        nargs='+',
        help='Save results to a file. Requires the "-o" flag')
    parser.add_argument(
        '-s',
        '--save-as',
        help='File name to save results as',
        default='scan results')

    args = parser.parse_args()

    if pathsep == ':':
        pathsep = '/'

    if not args.input_file and not args.targets:
        print('No targets specified. I don\'t know what you expected...')
        exit(1)
    if args.report and args.save_as == 'scan results':
        print(
            'No destination file specified. Will use default of "scan results"'
        )
    if args.save_as and args.save_as != 'scan results' and not args.report:
        print(('A file to save to was specified but no format was passed. '
               'Exiting so you may remedy this.'))
        exit(1)
    if args.save_as and args.report:
        outfile_path, outfile_name = abspath(args.save_as).rsplit(pathsep, 1)
    if args.input_file:
        with open(abspath(args.input_file)) as f:
            targets = parse_targets(f.readlines())
    if args.targets:
        targets = parse_targets(args.targets)
    # Remove duplicates
    targets = list(set(targets))

    all_results = []
    ports = parse_ports(args.ports)
    for choice in args.transport:
        if choice == 'icmp':
            all_results.append(
                (choice, scan_actions[choice](
                    targets, ports, verbose=False)))
        else:
            results = []
            for target in targets:
                results.append(
                    (target, scan_actions[choice](
                        target, ports, verbose=False)))
            all_results.append((choice, results))

    report = defaultdict(dict)

    for method, results in all_results:
        if method == 'icmp':
            print('The following devices were reachable via ICMP:')
            alive = results[0]
            for ip in alive:
                print(ip)
            if args.report and 'csv' in args.report:
                with open(
                        outfile_path + pathsep + 'icmp_' + outfile_name,
                        'w') as f:
                    f.writelines(list(map(lambda a: a + '\n', alive)))
            if args.report and 'pdf' in args.report:
                print('Sorry, ICMP PDF reports not available at this time!')
            print()
        else:
            print(
                'The following devices had these ports open when scanning',
                method.upper() + ':')
            pdf_compile = []
            csv_compile = []
            for target, successes in results:
                if successes:
                    print(' - Host', target +
                          ':', ', '.join([str(port) for port, _ in successes]))
                    if method != 'udp':
                        pdf_compile.append([success[1]
                                            for success in successes])
                    csv_compile.append(
                        ','.join(
                            [target] + [str(success[0])
                                        for success in successes]
                        ) + '\n')

            if args.report and 'pdf' in args.report and pdf_compile:
                SndRcvList(reduce(lambda x, y: x + y, pdf_compile)).pdfdump(
                    ''.join(
                        [
                            outfile_path,
                            pathsep,
                            method,
                            '_',
                            outfile_name,
                            '.pdf']))

            if args.report and 'csv' in args.report and csv_compile:
                with open(
                        ''.join([
                            outfile_path,
                            pathsep,
                            method,
                            '_',
                            outfile_name,
                            '.csv']), 'w') as f:
                    f.writelines(csv_compile)
