import time
import threading
from queue import Queue, PriorityQueue
import switchyard
from switchyard.lib.userlib import *

class Wait:
    def __init__(self, pkt, intf, dstip):
        self.packet = pkt
        self.lasttime = 0   # 上一次发送ARP请求的时间
        self.count = 0      # 累计发送ARP请求的次数
        self.interface = intf
        self.dstipaddr = dstip

    def forwarding(self, cache, net, repeat):
        if self.dstipaddr in cache.keys():
            # ARP缓存表中有匹配则替换相应地址后发送
            dstmac = cache[self.dstipaddr]
            self.packet[0].dst = str(dstmac)
            net.send_packet(self.interface.name, self.packet)
            return 0
        # 需要距离上次发送超过1秒且相同的目的地址还没发送过请求
        elif time.time() - self.lasttime >= 1 and self.dstipaddr not in repeat:
            if self.count < 5:          # 且发送次数不超过5次
                repeat.append(self.dstipaddr)
                # 构建ARP请求包，发送并更新状态
                ether = Ethernet()
                # ether.src = self.packet[0].src
                ether.src = self.interface.ethaddr
                ether.dst = 'ff:ff:ff:ff:ff:ff'
                ether.ethertype = EtherType.ARP
                arp = Arp(operation=ArpOperation.Request,
                          senderhwaddr=self.interface.ethaddr,
                          senderprotoaddr=self.interface.ipaddr,
                          targethwaddr='ff:ff:ff:ff:ff:ff',
                          targetprotoaddr=self.dstipaddr)
                arppacket = ether + arp
                self.lasttime = time.time()
                net.send_packet(self.interface.name, arppacket)
                self.count += 1
                return 1
            else:
                return - 1
        else:
            return 1



class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.my_interfaces = self.net.interfaces()
        self.cache = {}
        self.forwarding_table = {}
        self.build_forwarding_table()
        self.waiting_queue = []
        
    def build_forwarding_table(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        for intf in self.my_interfaces:
            # print(intf)
            ipaddr = IPv4Address(int(intf.ipaddr) & int(intf.netmask))  # 通过掩码取出端口的IP地址所在的子网
            key = IPv4Network(str(ipaddr) + '/' + str(intf.netmask))    # 子网地址与掩码组合形成键
            self.forwarding_table[key] = ['', intf.name]                     # 下一跳地址用空字符''代替

        
        with open("/home/njucs/lab/lab-4/lab-4-tongqianpolan/forwarding_table.txt") as file_object:
            for line in file_object:
                info = line.rsplit()        # 去掉行尾回车
                if info:                    # 确保不是空行
                    key = IPv4Network(info[0] + '/' + info[1])  # 子网地址与掩码组合
                    self.forwarding_table[key] = info[2:]
        
        for item in self.forwarding_table.items():
            print(item)
    
    def start(self):
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
                self.handle_packet(recv)
            except NoPackets:
                log_info("No packets available in recv_packet")
                
            except Shutdown:
                log_info("Got shutdown signal")
                break

            self.handle_waiting_packet()
        self.stop()

    def stop(self):
        self.net.shutdown()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, pkt = recv
        log_info("Got a packet: {}".format(str(pkt)))

        # 将非ARP和IPv4的包抛弃
        arp = pkt.get_header(Arp)
        ipv4 = pkt.get_header(IPv4)
        
        if arp:
            # 更新ARP缓存表
            self.cache[arp.senderprotoaddr] = arp.senderhwaddr
            for key, value in self.cache.items():
                print(key, "\t", value)
            print()
            if arp.operation == ArpOperation.Request:
                for intf in self.my_interfaces:
                    if arp.targetprotoaddr == intf.ipaddr:
                        packet = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                        self.net.send_packet(intf.name, packet)
                        log_info("send packet {} to {}".format(packet, intf.name))
        elif ipv4:
            # 准备转发数据包的预处理
            pkt[1].ttl = pkt[1].ttl - 1
            prefix = 0
            net = IPv4Network('0.0.0.0/0')
            # 抛弃目标地址为路由器的包
            run = True
            for intf in self.my_interfaces:
                if pkt[1].dst == intf.ipaddr:
                    run = False
                    break
            
            if run:
                # 最长前缀匹配
                for key in self.forwarding_table.keys():
                    if pkt[1].dst in key:
                        if key.prefixlen > prefix:
                            net = key
                            prefix = key.prefixlen
                # 抛弃无法匹配的包
                if prefix != 0:
                    # 确定下一跳地址
                    if self.forwarding_table[net][0]:
                        dstipaddr = IPv4Address(self.forwarding_table[net][0])
                    else:
                        dstipaddr = pkt[1].dst
                    # 找出转发端口
                    interface = self.forwarding_table[net][1]
                    for intf in self.my_interfaces:
                        if intf.name == interface:
                            router_intf = intf
                            break
                    pkt[0].src = router_intf.ethaddr
                    # 将数据包和端口、目标地址打包成一个类对象加入队列
                    self.waiting_queue.append(Wait(pkt, router_intf, dstipaddr))

    def handle_waiting_packet(self):
        # 对队列中所有包尝试转发并删除某些包（成功转发和ARP请求将超过5次）
        repeat = []         # 存储之前已经发送过ARP请求的包的目的地址
        to_delete = []      # 存储将要被删除的包
        for item in self.waiting_queue:
            flag = item.forwarding(self.cache, self.net, repeat)
            if flag == 0:
                to_delete.append(item)
            elif flag == -1:
                tempip = item.dstipaddr
                for temp in self.waiting_queue:
                    if temp.dstipaddr == tempip:
                        to_delete.append(temp)
        for i in to_delete:
            self.waiting_queue.remove(i)

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()