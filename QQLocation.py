#!/usr/bin/python
# -*- coding: UTF-8 -*-


print u'''
运行以后,当出现'监听中,请开始QQ通话..'
请使用QQ 与对方进行QQ通话(QQ电话)并减少流量通信
当发现以后会在控制台进行打印
'''

try:
    from scapy.all import IP
    from scapy.arch.windows import compatibility
    from scapy.all import log_runtime, MTU, ETH_P_ALL, PcapTimeoutElapsed, plist
except:
    print '[>]没有安装scapy,需要安装scapy'

def PacketHandler(pkt) :
    try:
        if pkt.len==100:
            sip = pkt.getlayer(IP).src
            dip = pkt.getlayer(IP).dst
            print sip+'--->'+dip
            # 排除局域网 10. 172. 192.168.开头
            if not dip.startswith('10.') and not dip.startswith('172.') and not dip.startswith('192.168.'):
                print u'对方可疑IP',pkt.getlayer(IP).dst
    except Exception,e:
        print e

def runGo():
    print u'监听中,请开始QQ通话..'
    compatibility.log_runtime = log_runtime
    compatibility.MTU = MTU
    compatibility.PcapTimeoutElapsed = PcapTimeoutElapsed
    compatibility.ETH_P_ALL = ETH_P_ALL
    compatibility.plist = plist
    compatibility.sniff(100,prn = PacketHandler,filter="udp")

    print u'已停止监听'

runGo()
