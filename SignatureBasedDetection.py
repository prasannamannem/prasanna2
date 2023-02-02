from threading import Thread
from scapy.all import *
from datetime import datetime
from tkinter import *
from tkinter import messagebox

class SignatureBasedDetection(Thread):
    __flagsTCP = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
        }
    __ip_cnt_TCP = {}

    malicious = 0
        
    def __init__(self, queue, text):
        Thread.__init__(self)
        self.stopped = False
        self.queue = queue
        self.text = text
        self.malicious = 0
        self. __ip_cnt_TCP.clear()
        

    def stop(self):
        self.stopped = True

    def getMalicious(self):
        return self.malicious

    def stopfilter(self, x):
        return self.stopped

    def detect_TCPflood(self, packet):
        if UDP in packet:
            print("========"+str(packet))
        if TCP in packet:
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            stream = pckt_src + ':' + pckt_dst

        if stream in self.__ip_cnt_TCP:
            self.__ip_cnt_TCP[stream] += 1
        else:
            self.__ip_cnt_TCP[stream] = 1

        for stream in self.__ip_cnt_TCP:
            pckts_sent = self.__ip_cnt_TCP[stream]
            if pckts_sent > 255:
                src = stream.split(':')[0]
                dst = stream.split(':')[1]
                self.malicious = self.malicious + 1
                print("Possible Flooding Attack from %s --> %s --> %s"%(src,dst,str(pckts_sent)))
                self.text.insert(END,"Possible Flooding Attack from %s --> %s --> %s\n"%(src,dst,str(pckts_sent)))
            else:
                src = stream.split(':')[0]
                dst = stream.split(':')[1]
                print("Normal traffic from %s --> %s --> %s"%(src,dst,str(pckts_sent)))
                #self.text.insert(END,"Normal traffic from %s --> %s --> %s"%(src,dst,packet.ttl))
        

    def process(self, queue):
        self.malicious = 0
        while not queue.empty():
            pkt = queue.get()
            if IP in pkt:
                pckt_src=pkt[IP].src
                pckt_dst=pkt[IP].dst
                #print("IP Packet: %s  ==>  %s  , %s"%(pckt_src,pckt_dst,str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))), end=' ')

            if TCP in pkt:
                src_port=pkt.sport
                dst_port=pkt.dport
                #print(", Port: %s --> %s, "%(src_port,dst_port), end='')
                #print([__flagsTCP[x] for x in pkt.sprintf('%TCP.flags%')])
                self.detect_TCPflood(pkt)
        queue.empty()        
        messagebox.showinfo("Signature Based Malicious Packet Detection","Signature Based Malicious Packet Detection : "+str(self.getMalicious()))


    def run(self):
        print("Sniffing started. ")
        self.process(self.queue)

        
