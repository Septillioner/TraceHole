#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet
 
import socket, sys
from struct import *
import time
from threading import Thread
class PacketManager(object):
	"""docstring for PacketManager"""
	def __init__(self):
		super(PacketManager, self).__init__()
		self.PacketList = []
		self.AnalyzedPacketCount = 0
		self.Continuous = False
		self.DoneSniffer = False
		try:
    		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		except socket.error , msg:
    		print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    		sys.exit()
	def OpenPacket(self,packet):
		self.PacketList.append(Packet())
	def _Sniff(self):
		while not self.DoneSniffer:
			if(not self.Continuous):
				time.sleep(1)
				continue
			packet = s.recvfrom(65565)
			self.OpenPacket(packet)
	def StartSniff(self):
		self.Continuous = True
	def StopSniff(self):
		self.Continuous = False
	def ToggleSniff(self):
		self.Continuous = not self.Continuous
	def DestroySniff(self):
		self.DoneSniffer = True
	def Sniff(self):
		self.SniffThread = Thread(target=self._Sniff)
		self.SniffThread.Start()
class Packet(object):
	"""docstring for Packet"""
	def __init__(self, packet_structed=None):
		super(Packet, self).__init__()
		self.packet_structed = packet_structed
		packet = packet_structed
		packet = packet[0]
     	ip_header = packet[0:20]
    	iph = unpack('!BBHHHBBH4s4s' , ip_header)
    	version_ihl = iph[0]
    	version = version_ihl >> 4
    	ihl = version_ihl & 0xF
    	iph_length = ihl * 4
    	ttl = iph[5]
    	protocol = iph[6]
    	s_addr = socket.inet_ntoa(iph[8]);
	    d_addr = socket.inet_ntoa(iph[9]); 
    	tcp_header = packet[iph_length:iph_length+20]
     	tcph = unpack('!HHLLBBHHH' , tcp_header)
     	source_port = tcph[0]
    	dest_port = tcph[1]
    	sequence = tcph[2]
    	acknowledgement = tcph[3]
    	doff_reserved = tcph[4]
    	tcph_length = doff_reserved >> 4
    	h_size = iph_length + tcph_length * 4
    	data_size = len(packet) - h_size
     	data = packet[h_size:]
     	self.ip_header = ip_header
     	self.iph = iph
     	self.version_ihl = version_ihl
     	self.version = version
     	self.ihl = ihl
     	self.iph = iph
def main():
	pckgm = PacketManager()
	pckgm.Sniff()
def gui():
	pass
if __name__ == '__main__':
	main()
