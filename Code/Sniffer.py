#                                  Muhammad Ashir | 22K-4504


from scapy.all import sniff, IP
from scapy.utils import PcapWriter

#import socket

from tkinter import *
from threading import Thread, Event

from ProtocolsClasses import TCP, UDP, HTTP, Ethernet, IPv4, ICMP, format_multi_line



packets = []


def get_ipv4_src_dest(packet):
    ipv4 = IPv4(packet.data)
    return ipv4.src, ipv4.target


def get_ipv4_protocol(packet):
    ipv4 = IPv4(packet.data)

    if ipv4.proto == 1:
        return 'ICMP'
    elif ipv4.proto == 6:
        tcp = TCP(ipv4.data)
        if tcp.src_port == 80 or tcp.dest_port == 80:
            return 'HTTP'
        return 'TCP'
    elif ipv4.proto == 17:
        return 'UDP'
    else:
        return 'OTHER'


def get_color_code(protocol):
    if protocol == 'ICMP':
        return '#fbb5df'
    if protocol == 'HTTP':
        return '#80e6ff'
    if protocol == 'TCP':
        return '#29fbc1'
    if protocol == 'UDP':
        return '#448888'
    if protocol == 'OTHER':
        return '#fff6a7'
    else:
        return '#fff6a7'


class Sniffer_GUI():

    def __init__(self, root):
        self.root = root
        self.filter = StringVar()
        self.root.title('Packet Sniffer')
        self.root.geometry("630x500")
        self.packet_serial = 0 
        self.packet_button = []
        self.packet_btn_list = []

        self.create_GUI()

    def create_GUI(self):

        self.start_capture_button = Button(self.root, text="START CAPTURE", width=40, height=1, command=self.start_capture, borderwidth=1, relief="solid")
        self.start_capture_button.place(x=15, y=10, height=30)

        self.stop_capture_button = Button(self.root, text="STOP CAPTURE", width=25, height=1, command=self.stop_capture, borderwidth=1, relief="solid", state='disabled')
        self.stop_capture_button.place(x=380, y=10, height=30)

        filter_label = Label(self.root, text="Filter ", font=("Arial", 15))
        filter_label.place(x=15, y=60)

        self.entry_box_filter = Entry(self.root, textvariable=self.filter, width=35, bg="white", borderwidth=2, relief="groove")
        self.entry_box_filter.place(x=75, y=60, height=30)

        self.apply_filter_button = Button(self.root, text="Apply Filter", width=10, height=1, command=self.apply_filter, borderwidth=1, relief="solid")
        self.apply_filter_button.place(x=380, y=60, height=30)

        self.remove_filter_button = Button(self.root, text="Remove Filter", width=10, height=1, command=self.remove_filter, borderwidth=1, relief="solid")
        self.remove_filter_button.place(x=500, y=60, height=30)

        capture_feed_label = Label(self.root, text="Capture Feed", font=("Arial", 13))
        capture_feed_label.place(x=15, y=100)

        self.reply_frame = Frame(self.root, borderwidth=1, relief="solid")
        self.reply_frame.place(x=15, y=130)

        self.reply_canvas = Canvas(self.reply_frame, width=580, height=350)
        self.reply_canvas.pack(side=LEFT, fill=BOTH, expand=YES)

        reply_scrollbar = Scrollbar(self.reply_frame, orient=VERTICAL, command=self.reply_canvas.yview)
        reply_scrollbar.pack(side=RIGHT, fill=Y, pady=10)

        self.sframe = Frame(self.reply_canvas, width=580, height=340)
        self.sframe.pack()
        self.sframe.bind("<Configure>", lambda e: self.reply_canvas.configure(scrollregion=self.reply_canvas.bbox("all")))

        self.reply_canvas.configure(yscrollcommand=reply_scrollbar.set)
        self.reply_canvas.bind('<Configure>', lambda e: self.reply_canvas.configure(scrollregion=self.reply_canvas.bbox("all")))

        self.reply_canvas.create_window((0,0), window=self.sframe, anchor="nw")

    def start_capture(self):
        print('Starting capture...')
        self.start_capture_button['state'] = 'disabled'
        self.stop_capture_button['state'] = 'normal'

        self.sniffer = PacketSniffer(guiobject=self)
        self.sniffer_thread = Thread(target=self.sniffer.sniff)
        self.sniffer_thread.start()

    def add_packet_button(self, serial_number, protocol, src, dest, packet):
        color = get_color_code(protocol)

        if self.filter.get() == '' or self.filter.get().upper() == protocol:
            btn = Button(self.sframe, text=f'{serial_number}\t Source:{src}\t Destination: {dest}\t Protocol: {protocol}', width=68, bg=color, command=lambda pkt=packet: self.expand_packet(pkt), borderwidth=1, relief="solid", anchor="w")
            btn.pack(padx=0, pady=2)
            self.packet_button.append(btn)
            self.packet_btn_list.append(packet)

    def expand_packet(self, packet):
        newWindow = Toplevel(self.root)
        newWindow.title("Packet Details")
        newWindow.geometry("500x600")

        ipv4 = IPv4(packet.data)
        Label(newWindow, text=f'Version: {ipv4.version}').pack(padx=10, anchor="w")
        Label(newWindow, text=f'Header Length: {ipv4.header_length} bytes').pack(padx=10, anchor="w")
        Label(newWindow, text=f'TTL: {ipv4.ttl}').pack(padx=10, anchor="w")
        Label(newWindow, text=f'Protocol: {ipv4.proto}').pack(padx=10, anchor="w")
        Label(newWindow, text=f'Source: {ipv4.src}').pack(padx=10, anchor="w")
        Label(newWindow, text=f'Target: {ipv4.target}').pack(padx=10, anchor="w")

        if ipv4.proto == 1:
            icmp = ICMP(ipv4.data)
            Label(newWindow, text='ICMP Packet').pack(padx=10, pady=10, anchor="w")
            Label(newWindow, text=f'Type: {icmp.type}').pack(padx=10, anchor="w")
            Label(newWindow, text=f'Code: {icmp.code}').pack(padx=10, anchor="w")
            Label(newWindow, text=f'Checksum: {icmp.checksum}').pack(padx=10, anchor="w")
            Label(newWindow, text='ICMP Data:').pack(padx=10, pady=10, anchor="w")
            data = format_multi_line(icmp.data)
            Label(newWindow, text=data).pack(padx=10, pady=10, anchor="w")

        elif ipv4.proto == 6:
            tcp = TCP(ipv4.data)
            Label(newWindow, text='TCP Segment').pack(padx=10, pady=10, anchor="w")
            Label(newWindow, text=f'Source Port: {tcp.src_port}').pack(padx=10, anchor="w")
            Label(newWindow, text=f'Destination Port: {tcp.dest_port}').pack(padx=10, anchor="w")
            Label(newWindow, text=f'Sequence: {tcp.sequence}').pack(padx=10, anchor="w")
            Label(newWindow, text=f'Acknowledgment: {tcp.acknowledgment}').pack(padx=10, anchor="w")
            Label(newWindow, text='Flags:').pack(padx=10, pady=10, anchor="w")
            Label(newWindow, text=f'URG: {tcp.flag_urg}, ACK: {tcp.flag_ack}, PSH: {tcp.flag_psh}').pack(padx=10, anchor="w")
            Label(newWindow, text=f'RST: {tcp.flag_rst}, SYN: {tcp.flag_syn}, FIN: {tcp.flag_fin}').pack(padx=10, anchor="w")

            if len(tcp.data) > 0:
                if tcp.src_port == 80 or tcp.dest_port == 80:
                    Label(newWindow, text='HTTP Data:').pack(padx=10, pady=10, anchor="w")
                    try:
                        http = HTTP(tcp.data)
                        http_info = str(http.data).split('\n')
                        for line in http_info:
                            Label(newWindow, text=str(line)).pack(padx=10, anchor="w")
                    except:
                        data = format_multi_line(tcp.data)
                        Label(newWindow, text=data).pack(padx=10, pady=10, anchor="w")
                else:
                    Label(newWindow, text='TCP Data:').pack(padx=10, pady=10, anchor="w")
                    data = format_multi_line(tcp.data)
                    Label(newWindow, text=data).pack(padx=10, pady=10, anchor="w")

        elif ipv4.proto == 17:
            udp = UDP(ipv4.data)
            Label(newWindow, text='UDP Segment').pack(padx=10, pady=10, anchor="w")
            Label(newWindow, text=f'Source Port: {udp.src_port}').pack(padx=10, anchor="w")
            Label(newWindow, text=f'Destination Port: {udp.dest_port}').pack(padx=10, anchor="w")
            Label(newWindow, text=f'Length: {udp.size}').pack(padx=10, anchor="w")
            if len(udp.data) > 0:
                Label(newWindow, text='UDP Data:').pack(padx=10, pady=10, anchor="w")
                data = format_multi_line(udp.data)
                Label(newWindow, text=data).pack(padx=10, pady=10, anchor="w")

        else:
            Label(newWindow, text='Other IPv4 Data:').pack(padx=10, pady=10, anchor="w")
            data = format_multi_line(ipv4.data)
            Label(newWindow, text=data).pack(padx=10, pady=10, anchor="w")

    def apply_filter(self):
        self.clear_scrollbar()
        filter_value = self.filter.get().upper()

        for serial_number, proto, pkt in packets:
            if proto == filter_value:
                src, dest = get_ipv4_src_dest(pkt)
                self.add_packet_button(serial_number, proto, src, dest, pkt)
        print('Filter applied')

    def clear_scrollbar(self):
        while len(self.packet_button) > 0:
            packet = self.packet_button.pop()
            packet.destroy()

    def remove_filter(self):
        self.entry_box_filter.delete(0, END)
        self.clear_scrollbar()

        for serial_number, proto, pkt in packets:
            src, dest = get_ipv4_src_dest(pkt)
            self.add_packet_button(serial_number, proto, src, dest, pkt)
        print('Filter removed')

    def stop_capture(self):
        print('Stopping capture now.')
        if hasattr(self, 'sniffer'):
            self.sniffer.stop_sniffing.set()  
        self.start_capture_button['state'] = 'normal'
        self.stop_capture_button['state'] = 'disabled'



class PacketSniffer():

    def __init__(self, guiobject=None):
        self.guiobj = guiobject
        self.stop_sniffing = Event()
        self.pcap_writer = PcapWriter("capture.pcap", append=True, sync=True)
        print('Initialized PcapWriter: capture.pcap')

    def sniff(self):
        sniff(prn=self.process_packet, store=0, stop_filter=self.should_stop_sniffing)

    def process_packet(self, scapy_packet):
        raw_data = bytes(scapy_packet)
        eth = Ethernet(raw_data)
        if eth.proto == 8:  
            self.guiobj.packet_serial += 1 
            serial_number = self.guiobj.packet_serial
            proto = get_ipv4_protocol(eth)
            packets.append((serial_number, proto, eth))
            src, dest = get_ipv4_src_dest(eth)
            self.guiobj.add_packet_button(serial_number, proto, src, dest, eth)
        self.pcap_writer.write(scapy_packet)

    def should_stop_sniffing(self, packet):
        return self.stop_sniffing.is_set()



if __name__ == "__main__":
    root = Tk()
    Sniffer_GUI(root)
    root.mainloop()
