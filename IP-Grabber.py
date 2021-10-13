import pyshark
import pyperclip

print('Omegle IP Grabber Started')

me = ['20.20.20.178', '20.20.20.21']
u = ''

cap = pyshark.LiveCapture(interface='Ethernet', bpf_filter='udp')
cap.sniff(packet_count=10)

def print_ip_info(pkt):
    global u
    try:
        if int(pkt.captured_length) == 106:
            s = pkt.ip.dst
            if s not in me:
                if str(s) != u:
                    u = str(s)
                    print('\n---------- New Connection ----------\n')
                    print(u)
                    pyperclip.copy(u)
                    print('\n------------------------------------\n')
    except:
        print('No Destination IP')

cap.apply_on_packets(print_ip_info)
