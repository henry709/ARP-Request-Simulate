from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr1
import netifaces as ni
import platform
import netifaces
import time


def get_connection_name_from_guid(iface_guids):
    if platform.system() == "Windows":
        import winreg as wr
        iface_names = ['(unknown)' for i in range(len(iface_guids))]
        reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
        reg_key = wr.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
        for i in range(len(iface_guids)):
            try:
                reg_subkey = wr.OpenKey(reg_key, iface_guids[i] + r'\Connection')
                iface_names[i] = wr.QueryValueEx(reg_subkey, 'Name')[0]
            except FileNotFoundError:
                pass
        return zip(iface_guids, iface_names)


def get_ifname(ifname):
    if platform.system() == "Linux":
        return ifname
    elif platform.system() == "Windows":
        import winreg as wr
        x = ni.interfaces()
        for i in get_connection_name_from_guid(x):
            if i[1] == ifname:
                return i[0]
    else:
        print('System not support')


def get_mac_address(ifname):  
    return netifaces.ifaddresses(get_ifname(ifname))[netifaces.AF_LINK][0]['addr']


def get_ip_address(ifname):  
    return ifaddresses(get_ifname(ifname))[AF_INET][0]['addr']


def get_ipv6_address(ifname):  
    return ifaddresses(get_ifname(ifname))[AF_INET6][0]['addr']


def arp_request(dst, ifname):  
    hwsrc = get_mac_address(ifname)
    psrc = get_ip_address(ifname)
    try:
        arp_pkt = sr1(ARP(op=1, hwsrc=hwsrc, psrc=psrc, pdst=dst), timeout=5, verbose=False)
        return dst, arp_pkt.getlayer(ARP).fields['hwsrc']
    except AttributeError:
        return dst, None


if __name__ == '__main__':
    hostname = input('Please enter the destination IP address to be requested:')
    iface = input('Please enter the name of the local nic interface:')
    print('requesting', hostname, 'MAC address, please wait!')
    time.sleep(2)
    arp_result = arp_request(hostname, iface)
    if arp_result[1] != None:
        print('The request result is as follows:')
        print('HOST：', arp_result[0], 'MAC address：', arp_result[1])
    else:
        print('The request failed. Please make sure the network is accessible!')
