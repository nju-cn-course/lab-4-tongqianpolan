#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

class PendingPacket:
    def __init__(self, pkt, next_hop_ip, out_iface):
        self.pkt = pkt
        self.next_hop_ip = next_hop_ip
        self.out_iface = out_iface
        self.last_sent_time = 0
        self.retry_count = 0

class ArpCacheEntry:
    def __init__(self, mac_addr):
        self.mac_addr = mac_addr
        self.timestamp = time.time()

class ArpTable:
    def __init__(self):
        self.cache = {}

    def add_or_update(self, ip_addr, mac_addr):
        if mac_addr == 'ff:ff:ff:ff:ff:ff':
            print(f"Warning: Receive broadcast MAC for {ip_addr}, ignoring.")
            return
        self.cache[ip_addr] = ArpCacheEntry(mac_addr)
        self.print_table()

    def lookup(self, ip_addr):
        entry = self.cache.get(ip_addr)
        if entry:
            return entry.mac_addr
        return None

    def print_table(self):
        print("Current Arp Table:")
        for ip, entry in self.cache.items():
            print(f"IP: {ip}, MAC: {entry.mac_addr}, Age: {int(time.time() - entry.timestamp)}s")

def ipv4_to_int(ip_str):
    return int(IPv4Address(ip_str))

def int_to_ipv4(ip_int):
    return str(IPv4Address(ip_int))

def get_work_address(ip_str, mask_str):
    ip_int = ipv4_to_int(ip_str)
    mask_int = ipv4_to_int(mask_str)
    network_int = ip_int & mask_int
    prefix_len = bin(mask_int).count('1')
    #prefix_len = IPv4Network(f'{ip_str}/{mask_str}').prefixlen
    return network_int, prefix_len

def build_forwarding_table(net_interfaces, forwarding_table_filename):
    forwarding_table = []
    for intf in net_interfaces:
        if intf.ipaddr is not None and intf.netmask is not None:
            netmask_str = str(intf.netmask)
            ip_str= str(intf.ipaddr)
            network_int, _ = get_work_address(ip_str, netmask_str)
            entry = {
                'network': int_to_ipv4(network_int),
                'netmask': netmask_str,
                'next_hop': '0.0.0.0',
                'interface': intf.name
            }
            forwarding_table.append(entry)

    with open(forwarding_table_filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) != 4:
                continue
            network_int, _ = get_work_address(parts[0], parts[1])
            entry = {
                'network': int_to_ipv4(network_int),
                'netmask': parts[1],
                'next_hop': parts[2],
                'interface': parts[3],
            }
            forwarding_table.append(entry)
    
    return forwarding_table


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces = list(self.net.interfaces())
        self.arp_table = {}
        self.pending_packets = []
        self.forwarding_table = build_forwarding_table(self.interfaces, '/home/njucs/lab/lab-4/lab-4-tongqianpolan/forwarding_table.txt')
        print("router:", self.forwarding_table)
        print("interfaces list:", [(i.name, i.ipaddr, i.netmask) for i in self.interfaces])
       

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        eth = packet.get_header(Ethernet)
        if eth is None:
            return

        iface = self.get_interface_by_name(ifaceName)

        if eth.dst not in (EthAddr('ff:ff:ff:ff:ff:ff'), iface.ethaddr):
            return

        if eth.ethertype == EtherType.ARP:
            self.handle_arp(packet, ifaceName)
        
        elif eth.ethertype == EtherType.IPv4:
           self.handle_ip4(packet, ifaceName)

    def get_interface_by_name(self, name):
        #print(f"all interfaces: {self.interfaces}")
        #print(name)
        for intf in self.interfaces:
            print(f"interface name: {intf.name}, name: {name}")
            if intf.name == name:
                return intf
        return None

    def forward_packet(self, pkt, next_hop_ip, out_iface_name):
        out_iface = self.get_interface_by_name(out_iface_name)
        print(out_iface, out_iface_name)
        if not out_iface:
            log_info(f"interface {out_iface_name} not found")
            return

        if next_hop_ip in self.arp_table:
            try:
                eth = Ethernet()
                eth.src = out_iface.ethaddr
                eth.dst = EthAddr(self.arp_table[next_hop_ip])
                eth.ethertype = EtherType.IPv4
                pkt[0] = eth
                self.net.send_packet(out_iface_name, pkt)
                log_info(f"forwarded packet to {next_hop_ip} via {out_iface_name}")
            except Exception as e:
                log_info(f"failed to forward packet: {e}")
        else:
            self.queue_packet(pkt, next_hop_ip, out_iface)

    def queue_packet(self, pkt, next_hop_ip, out_iface):
        pending = PendingPacket(pkt, next_hop_ip, out_iface)
        pending.last_sent_time = time.time() - 1
        #self.send_arp_request(pending)
        self.pending_packets.append(pending)

    def handle_ip4(self, packet, ifaceName):
        ipv4 = packet.get_header(IPv4)
        if ipv4.dst in [intf.ipaddr for intf in self.interfaces]:
            return
        ipv4.ttl -= 1
        if ipv4.ttl <= 0:
            return

        next_hop_ip = self.lookup_next_hop(str(ipv4.dst))
        if next_hop_ip is None:
            return

        out_iface_name = self.find_outgoing_interface(next_hop_ip)
        if out_iface_name is None:
            return

        print("forward normal packet")
        self.forward_packet(packet, next_hop_ip, out_iface_name)

    def handle_arp(self, packet, ifaceName):
        arp = packet.get_header(Arp)
        if arp.operation == ArpOperation.Reply:
            self.handle_arp_reply(packet)
        elif arp.operation == ArpOperation.Request:
            self.handle_arp_request(packet, ifaceName)

    def handle_arp_request(self, packet, ifaceName):
        arp = packet.get_header(Arp)
        log_info("interfaces:")
        for intf in self.interfaces:
            log_info(f" {intf.name}: ip={intf.ipaddr}, mask={intf.netmask}")
            if arp.targetprotoaddr == intf.ipaddr:
                reply = create_ip_arp_reply(
                    srchw = intf.ethaddr,
                    dsthw = arp.senderhwaddr,
                    srcip = intf.ipaddr,
                    targetip = arp.senderprotoaddr,
                )
                self.net.send_packet(ifaceName, reply)
                log_info(f"replied to arp request for {intf.ipaddr}")
                break

    def handle_arp_reply(self, pkt):
        arp = pkt.get_header(Arp)
        print("arp_table:", self.arp_table)
        self.arp_table[str(arp.senderprotoaddr)] = str(arp.senderhwaddr)
        #print("pending_packets:", self.pending_packets)
        
        forwarded_packets = [pending for pending in self.pending_packets if IPv4Address(pending.next_hop_ip) == arp.senderprotoaddr]
        for pending in forwarded_packets:
            print(f"pending next_hop_ip: {pending.next_hop_ip}, pending out_iface: {pending.out_iface.name}")
            self.forward_packet(pending.pkt, pending.next_hop_ip, pending.out_iface.name)
               
        self.pending_packets = [pending for pending in self.pending_packets if IPv4Address(pending.next_hop_ip) != arp.senderprotoaddr]
        # to_forward = []
        # for pending in self.pending_packets:
        #     if pending.next_hop_ip == str(arp.senderhwaddr):
        #         self.forward_packet(pending.pkt, pending.next_hop_ip, pending.out_iface.name)
        #         to_forward.append(pending)

        # for pending in to_forward:
        #     self.pending_packets.remove(pending)

    def lookup_next_hop(self, dst_ip):
        dst_ip_int = ipv4_to_int(dst_ip)
        best_match = None
        longest_prefix = -1
        for entry in self.forwarding_table:
            network_int, prefix_len = get_work_address(entry['network'], entry['netmask'])
            target_network_int = dst_ip_int & ipv4_to_int(entry['netmask'])
            if network_int == target_network_int:
                if prefix_len > longest_prefix:
                    longest_prefix = prefix_len
                    best_match = entry
        if best_match: 
            if best_match['next_hop'] == '0.0.0.0':
                return dst_ip
            else:
                return best_match['next_hop']
        return None

    def find_outgoing_interface(self, next_hop_ip):
        longest_prefix = -1
        selected_intf = None
        log_info("interfaces:")
        for intf in self.interfaces:
            if intf.ipaddr is None or intf.netmask is None:
                continue
            log_info(f" {intf.name}: ip={intf.ipaddr}, mask={intf.netmask}")
            netmask_str = str(intf.netmask)
            ip_str = str(intf.ipaddr)
            intf_network, intf_prefix = get_work_address(ip_str, netmask_str)
            target_network, _ = get_work_address(next_hop_ip, netmask_str)
            log_info(f"matching {next_hop_ip}: net_int={hex(intf_network)}, target={hex(target_network)}")
            if intf_network == target_network:
                if intf_prefix > longest_prefix:
                    longest_prefix = intf_prefix
                    selected_intf = intf
        if selected_intf:
            return selected_intf.name
        return None

    def send_arp_request(self, pending):
        # import pdb; pdb.set_trace()
        out_iface = pending.out_iface
        if not out_iface:
            log_info(f"interface {pending.out_iface} not found")
            return
       
       
        print(f"arp req: src_mac={out_iface.ethaddr}, src_ip={out_iface.ipaddr}, target_ip={pending.next_hop_ip}")
        # log_info(f"arp req for {pending.next_hop_ip} via {pending.out_iface}")
        try:
            arp_req = create_ip_arp_request(
                srchw = out_iface.ethaddr,
                srcip = out_iface.ipaddr,
                targetip = IPv4Address(pending.next_hop_ip)
            )
            print(f"send arp via interface: {pending.out_iface.name}")
            
            self.net.send_packet(out_iface.name, arp_req)
            pending.last_sent_time = time.time()
            pending.retry_count += 1

            return True

        except Exception as e:
            log_info(f"failed to send arp request: {e}")
            return False
        

    def checking_pending_packets(self):
        now = time.time()
        still_pending = []
        for pending in self.pending_packets:
            if pending.retry_count >= 5:
                log_info(f"ARP request for {pending.next_hop_ip} failed after 5 retries.")
                continue
            if now - pending.last_sent_time >= 1.0:
                if self.send_arp_request(pending):
                    still_pending.append(pending)
            else:
                 still_pending.append(pending)
        self.pending_packets = still_pending

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
            self.checking_pending_packets()

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
