#!/usr/bin

import pyshark
import socket
from scapy.all import *
import xlsxwriter
import signal


### You must install xlsxwriter, pyshark, and scapy ###
### You must run this script as a superuser ###
### You might need to run the script in the home directory ### 

# Calculates your IP address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()


# Capture packets on TCP Port 22 Only
capture = pyshark.LiveCapture(interface='eth0',bpf_filter='tcp port 22') #capture filter

# Dictionary that will be used to store data for each IP address connecting via SSH
captured_syn_packet = {}


# Excel file set up
workbook = xlsxwriter.Workbook('live_data.xlsx')
workbook_index = 1
worksheet = workbook.add_worksheet()
worksheet.write(0, 0, 'IP')
worksheet.write(0, 1, 'Client RTT')
worksheet.write(0, 2, 'Probing RTT')
worksheet.write(0, 3, 'VPN or Direct')


def print_callback(pkt):
    global workbook_index
    #check if the pkt's ip address is new
    #store the current ip address and time stamp for calulating VPN rtt
        #find next corresponding inbound time stamp
    #initiate SSH ping
    #store the outbound SSH ping time stamp
        #find next corresponding inbound time stamp

    try:
        # pkt.ip.src
        # pkt.ip.dst
        # pkt.tcp.seq
        # pkt.tcp.ack
        # pkt.tcp.len
        # pkt.tcp.flags
        # pkt.sniff_time
        # pkt.tcp.analysis_ack_rtt

         #print("Flags:",pkt.tcp.flags,"IP SRC:",pkt.ip.src,"IP DST:",pkt.ip.dst)
        
        # SYN Packet
        if (pkt.ip.src != my_ip and pkt['tcp'].flags == '0x00000002'):
            #print("SYN")
            captured_syn_packet[pkt.ip.src] = {'Status':'N'}
            print("IP address sending a [SYN] packet:",pkt.ip.src)

        # SYN ACK Packet
        elif (pkt.ip.src == my_ip and pkt['tcp'].flags == '0x00000012'):
            #print("SYN ACK")
            captured_syn_packet[pkt.ip.dst]['SA Packet'] = pkt.sniff_time
            

        # ACK Packet
        
        elif (pkt.ip.src != my_ip and pkt['tcp'].flags == '0x00000010'):
            if (pkt.ip.src in captured_syn_packet):
                    # Only calculates RTT if RTT has NOT been calculated yet
                    if (captured_syn_packet[pkt.ip.src]['Status'] == 'N'):
                        captured_syn_packet[pkt.ip.src]['A Packet'] = pkt.sniff_time
                        captured_syn_packet[pkt.ip.src]['Status'] = 'Y'
                        print("IP Address:",pkt.ip.src,"RTT:\033[1;32;40m", pkt.sniff_time - captured_syn_packet[pkt.ip.src]['SA Packet'],"\033[1;37;40m")
                        captured_syn_packet[pkt.ip.src]['Client RTT'] = pkt.sniff_time - captured_syn_packet[pkt.ip.src]['SA Packet']
                        # Probing source
                        rtt = sr1(IP(dst=pkt.ip.src)/TCP(dport=22,flags="S"))


        # Probing SYN Packet
        elif (pkt.ip.src == my_ip and pkt['tcp'].flags == '0x00000002'):
            if (pkt.ip.dst in captured_syn_packet):
                print("Sending a [SYN] Packet to:",pkt.ip.dst)
                captured_syn_packet[pkt.ip.dst]['Server S Packet'] = pkt.sniff_time

        # Probing SYN ACK Packet 
        elif (pkt.ip.src != my_ip and pkt['tcp'].flags == '0x00000012'):
            if (pkt.ip.src in captured_syn_packet):
                print("Before printing probe RTT")
                print("Probe RTT:\033[1;31;40m",pkt.sniff_time - captured_syn_packet[pkt.ip.src]['Server S Packet'],"\033[1;37;40m")
                captured_syn_packet[pkt.ip.src]['Probe RTT'] = pkt.sniff_time - captured_syn_packet[pkt.ip.src]['Server S Packet']

                # Will only write to excel file if both RTT-Client and RTT-Probe are not null
                if captured_syn_packet[pkt.ip.src]['Client RTT'] is not None and captured_syn_packet[pkt.ip.src]['Probe RTT'] is not None:
                    worksheet.write(workbook_index, 0, pkt.ip.src)
                    worksheet.write(workbook_index, 1, captured_syn_packet[pkt.ip.src]['Client RTT'])
                    worksheet.write(workbook_index, 2, captured_syn_packet[pkt.ip.src]['Probe RTT'])
                    #
                    # Determine if client is using a VPN or Direct
                    #

                    ### CHANGE IF STATEMENT TO THRESHOLD THAT WE COME UP WITH ###
                    if captured_syn_packet[pkt.ip.src]['Client RTT'].total_seconds() - captured_syn_packet[pkt.ip.src]['Probe RTT'].total_seconds() < 0.01: 
                        captured_syn_packet[pkt.ip.src]['V or D'] = "DIRECT"
                    else:
                        captured_syn_packet[pkt.ip.src]['V or D'] = "VPN"
                    worksheet.write(workbook_index, 3, captured_syn_packet[pkt.ip.src]['V or D'])
                    print("Added to excel file. Total items in excel file:",workbook_index)
                    workbook_index = workbook_index + 1
        else:
            return
                
    except AttributeError as e:
        pass


def start():
    print("Started capture...")

    try:
        capture.apply_on_packets(print_callback, timeout=100000)
    except:
        print("oops")
        start()


### Timeout
def handler(signum, frame):
    raise Exception("Done capturing.")


signal.signal(signal.SIGALRM, handler)

# Times out in x seconds
signal.alarm(30)

### Main
if __name__ == "__main__":
    try:
        start()
    except Exception as exc:
        print(exc)

### Saving excel file
workbook.close()
print("Excel file saved.")

