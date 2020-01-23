import ipaddress
import os.path
import re
import sys

import dns.rdtypes
import dns.rdatatype
import dns.zone

from collections import defaultdict

KNOWNZONES = ('.uio.no',)

SUPPORTED = (dns.rdatatype.SOA, dns.rdatatype.NS,
             dns.rdatatype.A, dns.rdatatype.AAAA,
             dns.rdatatype.CNAME, dns.rdatatype.MX, dns.rdatatype.NAPTR,
             dns.rdatatype.PTR,
             dns.rdatatype.SRV, dns.rdatatype.TXT,)


class Host:

    def __init__(self, name, ttl):
        self.name = name
        self.ttl = ttl
        self.ips = []
        self.cnames = []
        self.srvs = []
        self.mxs = []
        self.naptrs = []
        self.ptrs = []
        self.txts = []


hosts = {}
soa = {}
delegations = defaultdict(list)

def get_host(name, ttl):
    if name in hosts:
        return hosts[name]
    host = Host(name, ttl)
    hosts[name] = host
    return host

def strip_trailing_dot(data):
    data = str(data)
    if data.endswith('.'):
        return data[:-1]
    return data

def ip_from_reverse(rev):
    ip = ''
    if rev.endswith('ip6.arpa.'):
        rev = rev.replace('.ip6.arpa.', '')
        splitted = rev.split('.')
        it = reversed(splitted)
        for i in it:
            if ip:
                ip += ":"
            ip += "%s%s%s%s" % (i, next(it, '0'), next(it, '0'), next(it, '0'))
    elif revip.endswith('in-addr.arpa.'):
        ip = '.'.join(reversed(revip.split('.')[0:4]))
    return str(ipaddress.ip_address(ip))


filename = sys.argv[1]
basename = os.path.basename(filename)
#if 
zone = dns.zone.from_file(filename,
                          relativize=False)
zoneiter = iter(zone.iterate_rdatas())
#zoneiter = iter(zone.iterate_rdatasets())
zonename = str(zone.origin)[:-1]
soans = []
for name, ttl, data in zoneiter:
    name = name.to_text()
    if data.rdtype not in SUPPORTED:
        print(f"NOT supported: {data!r}")

    if data.rdtype == dns.rdatatype.SOA:
        soadata = data
    elif data.rdtype == dns.rdatatype.NS:
        name = strip_trailing_dot(name)
        if name == zonename:
            soans.append((ttl, data))
            continue
        delegations[name].append((ttl, data))
    elif data.rdtype == dns.rdatatype.PTR:
        revip = str(name).lower()
        ip = ip_from_reverse(revip)
        host = get_host(data.target, ttl)
        host.ptrs.append(ip)
    else:
        host = get_host(name, ttl)
        if data.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            host.ips.append(data)
        elif data.rdtype == dns.rdatatype.TXT:
            host.txts.append(data)
        elif data.rdtype == dns.rdatatype.MX:
            host.mxs.append(data)
        elif data.rdtype == dns.rdatatype.SRV:
            host.srvs.append(data)
        elif data.rdtype == dns.rdatatype.CNAME:
            host.cnames.append(data)
        elif data.rdtype == dns.rdatatype.NAPTR:
            host.naptrs.append(data)
        else:
            print(f"IMPLEMENT: {data.rdtype!r}, {data}")


# Replace first . with a @
email = re.sub(r'\.', '@', strip_trailing_dot(soadata.rname), 1)
nameservers = ' '.join([strip_trailing_dot(i[1]) for i in soans])
print(f"zone create {zonename} {email} {nameservers}")
tmp = ''
for attr in ('expire', 'retry', 'refresh'):
    tmp += f' -{attr} ' + str(getattr(soadata, attr))
print(f'zone set_soa {zonename} {tmp}')
print(f'zone set_default_ttl {zonename} {soadata.minimum}')

for name, nsdata in delegations.items():
    nameservers = ' '.join([strip_trailing_dot(i[1]) for i in nsdata])
    print(f'zone delegation_create {zonename} {name} {nameservers}')

for hostname, host in hosts.items():
    hostname = str(hostname)
    cmds = []
    for ip in host.ips:
        ip = str(ip)
        cmd = "host "
        if ":" in ip:
            cmd += 'aaaa_add'
        else:
            cmd += 'a_add'
        cmds.append(cmd + f" {hostname} {ip} -force")
    for mx in host.mxs:
        exchange = strip_trailing_dot(mx.exchange)
        cmds.append(f"host mx_add {hostname} {mx.preference} {exchange}")
    for realname in host.cnames:
        cmds.append(f"host cname_add {realname} {hostname}")
    for txt in host.txts:
        cmds.append(f"host txt_add {hostname} {txt}")
    for ptr in host.ptrs:
        cmds.append(f"host ptr_add {ptr} {hostname} -force")
    for srv in host.srvs:
        cmd = f"host srv_add -name {hostname} -priority {srv.priority} -weight {srv.weight} " \
              f"-port {srv.port} -host {srv.target}"
        cmds.append(cmd)
    for naptr in host.naptrs:
        flags = naptr.flags.decode('utf-8')
        service = naptr.service.decode('utf-8')
        regex = naptr.regexp.decode('utf-8')
        cmd = f"host naptr_add -name {hostname} -preference {naptr.preference} " \
              f"-order {naptr.order} -flag {flags} -service {service!r} " \
              f"-regex {regex!r} -replacement {naptr.replacement}"
        cmds.append(cmd)
    if cmds and not (host.cnames or host.srvs):
        force = ""
        for zone in KNOWNZONES:
            if hostname.endswith(zone):
                break
        else:
            force = "-force"
        cmds.insert(0, f"host add {hostname} {force}")
        if host.ttl != soadata.minimum:
            cmds.append(f"host ttl_set {hostname} {host.ttl}")
    for cmd in cmds:
        print(cmd)
