from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11
import os, signal, sys, string
from pyfiglet import Figlet
import time
import subprocess

#access_points = set()
whitelisted_aps = []
blacklisted_aps = []
channel = 1

def filter_beacon(p):
    """ Filter WiFi beacon and probe response packets. """
    return p.haslayer(Dot11Beacon)


def aps_scan(pkt):
    global channel
    global whitelisted_aps
    global blacklisted_aps
    parsed_list = []
    ap={}
    neighborap={}
    rougeap={}

    if (channel > 13):
        channel = 1
    channel_hopper()
    channel += 1

    # access_points.add(pkt[Dot11].addr3)
    ssid = pkt[Dot11].info
    bssid = pkt[Dot11].addr3
    signal_strength = pkt[RadioTap].dBm_AntSignal
    if signal_strength >= -30:
        sig_str = "Perfect"
    elif signal_strength >= -50 and signal_strength < -30:
        sig_str = "Excellent"
    elif signal_strength >= -60 and signal_strength < -50:
        sig_str = "Good"
    elif signal_strength >= -67 and signal_strength < -60:
        sig_str = "Fair"
    elif signal_strength >= -70 and signal_strength < -67:
        sig_str = "Not Good"
    elif signal_strength >= -80 and signal_strength < -70:
        sig_str = "Bad"
    elif signal_strength >= -90 and signal_strength < -80:
        sig_str = "Really Bad"
    channel = str(int(ord(pkt[Dot11Elt:3].info)))
    netstats = pkt[Dot11Beacon].network_stats()
    crypto = '/'.join(netstats['crypto'])
    ap.update({"ssid":ssid})
    ap.update({"mac":bssid})
    #ap.update({"sig_str":sig_str})
    ap.update({"channel":channel})
    ap.update({"crypto":crypto})

    if ap not in whitelisted_aps or blacklisted_aps:

        #print("SSID-------BSSID-------")
        print("\n" + ssid + " " + bssid + " " + sig_str+ " " + channel + " " + crypto)
        print(" ")
        print("1: Whitelist \n" +
              "2: Blacklist \n")
        selection = input("Whitelist(1) or Blacklist(2): ")

        if selection == 1:
            whitelisted_aps.append(ap)
            parsed_list.append(ap)
            print(bssid + " " + "on " + ssid + " " + "has been whitelisted")
        elif selection == 2:
            blacklisted_aps.append(ap)
            parsed_list.append(ap)
        else:
            print("Not a valid selection")


def monitor_scan(pkt):
    global channel
    global whitelisted_aps
    global blacklisted_aps
    ap={}

    if (channel > 13):
        channel = 1
    channel_hopper()
    channel += 1

    # access_points.add(pkt[Dot11].addr3)
    ssid = pkt[Dot11].info
    bssid = pkt[Dot11].addr3
    signal_strength = pkt[RadioTap].dBm_AntSignal
    if signal_strength >= -30:
        sig_str = "Perfect"
    elif signal_strength >= -50 and signal_strength < -30:
        sig_str = "Excellent"
    elif signal_strength >= -60 and signal_strength < -50:
        sig_str = "Good"
    elif signal_strength >= -67 and signal_strength < -60:
        sig_str = "Fair"
    elif signal_strength >= -70 and signal_strength < -67:
        sig_str = "Not Good"
    elif signal_strength >= -80 and signal_strength < -70:
        sig_str = "Bad"
    elif signal_strength >= -90 and signal_strength < -80:
        sig_str = "Really Bad"
    channel = str(int(ord(pkt[Dot11Elt:3].info)))
    netstats = pkt[Dot11Beacon].network_stats()
    crypto = '/'.join(netstats['crypto'])
    ap.update({"ssid": ssid})
    ap.update({"mac": bssid})
    #ap.update({"sig_str": sig_str})
    ap.update({"channel": channel})
    ap.update({"crypto": crypto})

    if (ap not in whitelisted_aps) or (ap in blacklisted_aps):
        print("Rogue AP Detected!!!")
        print(ssid + " " + bssid + " " + sig_str + " " + channel + " " + crypto)
        print("\n1. Whitelist\n" +
              "2. Blacklist\n")
        selection = input("Whitelist(1) or Blacklist(2): ")
        if selection == 1:
            whitelisted_aps.append(ap)
        elif selection == 2:
            blacklisted_aps.append(ap)
        else:
            print("Not a valid selection")

    #print(whitelisted_aps)
    #print(blacklisted_aps)


def channel_hopper():
    try:
        os.system("sudo iw dev %s set channel %d" % (interface, channel))
    except Exception, err:
        #logs_api.errors_log(str(err))

        pass


def init_scan():
    interface = raw_input("Interface: ")
    print("Setting interface to monitor mode...")
    os.system("ifconfig " + interface + " " + "down")
    os.system("iwconfig " + interface + " " + "mode monitor")
    os.system("ifconfig " + interface + " " + "up")
    print(interface + " " + "set to monitor mode")
    sniff(iface=interface, lfilter=filter_beacon, prn=aps_scan)
    main_menu()

def monitor():
    interface = raw_input("Interface: ")
    sniff(iface=interface, lfilter=filter_beacon, prn=monitor_scan)


def usage():
    print("\nList of commands \n\n" +
          "scan: Used to obtain initial whitelist \n" +
          "monitor: Set RogueAPDetector to monitor mode \n" +
          "show whitelist: Shows all whitelisted access points\n" +
          "show blacklist: Shows all blacklisted access points\n" +
          "help: Displays this menu \n" +
          "exit: Exits the program \n" +
          "clear: Clears the screen\n ")
    main_menu()

def main_menu():
    #global whitelisted_aps
    #global blacklisted_aps
    menu_cmd = str(raw_input("RogueAPDetector> "))

    if menu_cmd == "help":
        usage()
    elif menu_cmd == "scan":
        init_scan()
    elif menu_cmd == "monitor":
        monitor()
    elif menu_cmd == "show whitelist":
        print("\n Whitelisted Access Points--------------------------------------------------------------\n")
        for i in whitelisted_aps:
            print(i)
            print("\n")
        main_menu()
    elif menu_cmd == "show blacklist":
        print(blacklisted_aps)
        main_menu()
    elif menu_cmd == "exit":
        exit()
    elif menu_cmd == "clear":
        subprocess.call("clear")
        main_menu()
    else:
        print("Not a valid selection")
        main_menu()

def intro():
    f = Figlet(font='slant')
    word = 'ROGUE AP DETECTOR'
    print f.renderText(word)

def exit():
    sys.exit()

intro()
usage()
main_menu()