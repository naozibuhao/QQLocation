#!/usr/bin/python
# -*- coding:utf8 -*-


print u'''
正在加载相关模块请稍候...
'''
from time import sleep
import sys                                                                    
import signal
import platform 
import os 
try:
    from scapy.all import IP
    from scapy.arch.windows import compatibility
    from scapy.all import log_runtime, MTU, ETH_P_ALL, PcapTimeoutElapsed, plist
except:
    print u'[>]没有安装scapy,需要安装scapy'

try:
    import geoip2.database
except:
    print u'[>]没有安装geoip2,需要安装geoip2'
systemos = ''
# 判断当前系统
# 其实这里也没用 ,先写上后期可能会用上
def UsePlatform():
    global systemos
    sysstr = platform.system()
    if(sysstr =="Windows"):
      systemos = 'Windows'
    else: # 其实不准备支持linux  因为linux 上没有QQ
        if  sysstr =='Linux':
            print u'不支持Linux,因为Linux没有QQ'
        else:
          systemos = 'Windows'
      
UsePlatform()

# 清理屏幕 
# 这里用不上, 清理掉屏幕以后 历史消息就没有了
def clearScr():
    global systemos
    if systemos == 'Windows':
        cal = 'cls'
    else:
        cal = 'clear'
    os.system(cal)

#
def PacketHandler(pkt) :
    try:
        if pkt.len==100:
            sip = pkt.getlayer(IP).src
            dip = pkt.getlayer(IP).dst
            print sip+'--->'+dip
            # 排除局域网 10. 172. 192.168.开头
            if not dip.startswith('10.') and not dip.startswith('172.') and not dip.startswith('192.168.'):
                print u'对方可疑IP',pkt.getlayer(IP).dst
                getGps(dip)
        else:
            pass # 不做任何处理
#             print u'未发现数据包'
    except Exception,e:
        print e



def getGps(ip):
    
    GeoDB = geoip2.database.Reader('./db/GeoLite2-City.mmdb')
    res = GeoDB.city(ip)
    address = res.country.name + " " + res.city.name
    latitude = res.location.latitude
    longitude = res.location.longitude
    print u'所在地:',address
    print u'GPS信息:',latitude,',',longitude
    
    pass

def Menu():
    #clearScr() // 这里如果清理了 历史消息就看不到了
    print u'}----------------secquanQQLocation----------------------{'
    print u'[+] 1. 开始'  
    print u'[+] 99. 退出' 
    input = raw_input('secquanQQLocation~# ')
    #input = raw_input(unicode('请输入编号:','utf-8').encode('gbk'))
    if input == '1':
        runGo()
    elif input == '99':
            sys.exit()
    else:
        Menu()
        
def quit(signum, frame):  
    print ''  
    Menu()  
    
def runGo():
    
    print u'监听中,请开始QQ通话(电话/视频都可以)...Ctrl+C 结束监听'
    compatibility.log_runtime = log_runtime
    compatibility.MTU = MTU
    compatibility.PcapTimeoutElapsed = PcapTimeoutElapsed
    compatibility.ETH_P_ALL = ETH_P_ALL
    compatibility.plist = plist
    signal.signal(signal.SIGINT, quit)                                  
    signal.signal(signal.SIGTERM, quit)  
    # 循环监听
    while True:
        compatibility.sniff(100,prn = PacketHandler,filter="udp")
        print ''
        sleep(1)
    print u'已停止监听'
# 其实没啥用 就是为了让他输入一次 好知道可以开始了
enter = raw_input (unicode('模块加载完毕,输入任意键继续:','utf-8').encode('gbk'))
UsePlatform()
Menu()
#runGo()
