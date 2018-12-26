import socket
import struct
import binascii
import os
import sys
import re

d={}
print("Sniffer Running...\n")
if os.name=='nt':
		host=socket.gethostbyname(socket.gethostname()) #public network interface

		s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)

		intf=s.bind((host,0)) #RAW socket bind to Public interface

		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #include IP headers

		s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON) #recieve all packets

else:
		s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))		#socket.ntohs()|[socket.IPPROTO_ICMP/IP/TCP]
#set PROMISCUIOUS mode on eth0
#ntohs(0x0800) shows the protocol of interest...Defines the protocol {ETH_P_IP}
#ntohs(0x0003) shows the protocol of interest...Defines the protocol{ETH_P_ALL}

while True:
	try:
		pkt=s.recvfrom(65565) #recieve a package
		ethhead=pkt[0][0:14]
		eth=struct.unpack("!6s6s2s",ethhead) #H
		print("--------------------Ethernet Frame---------------------")
		print("Destination MAC        :\t",':'.join(re.findall('..', binascii.hexlify(eth[0]).decode("utf-8"))))
		print("Source MAC             :\t",':'.join(re.findall('..', binascii.hexlify(eth[1]).decode("utf-8"))))
		print("Protocol               :\t",binascii.hexlify(eth[2]).decode("utf-8"))

		if eth[2]==b'\x08\x06':
			arp_hdr = pkt[0][14:42]
			arp= struct.unpack("2s2s1s1s2s6s4s6s4s", arp_hdr)
			print("--------------------------ARP--------------------------")
			print("Hardware type             :\t", binascii.hexlify(arp[0]).decode("utf-8"))
			print("Protocol type             :\t", binascii.hexlify(arp[1]).decode("utf-8"))
			print("Hardware size             :\t", binascii.hexlify(arp[2]).decode("utf-8"))
			print("Protocol size             :\t", binascii.hexlify(arp[3]).decode("utf-8"))
			print("Opcode                    :\t ", binascii.hexlify(arp[4]).decode("utf-8"))
			print("Source MAC                :\t", ':'.join(re.findall('..',binascii.hexlify(arp[5]).decode("utf-8"))))
			print("Source IP                 :\t", socket.inet_ntoa(arp[6]))
			print("Destination MAC           :\t", ':'.join(re.findall('..',binascii.hexlify(arp[7]).decode("utf-8"))))
			print("Destination IP            :\t", socket.inet_ntoa(arp[8]))

			print('\n-------------------------DATA--------------------------')
			print(pkt[0][42:])
			print("\n")

		else:
			try:
				ipheader=pkt[0][14:34]
				ip_hdr=struct.unpack('!BBHHHBBH4s4s',ipheader)

				print('---------------------------IP--------------------------')
				print("Version                :\t" ,ip_hdr[0]>>4)	#get upper nibble version & it's ver length >>4
				print("DSCP & ECN             :\t",ip_hdr[1])
				print("IP Header Length       :\t",ip_hdr[0] & 0xF)	#get lower nibble header length
				print("Packet ID              :\t",ip_hdr[3])
				print("Flags/Frags Offset     :\t",ip_hdr[4] & 0x1FFF)	#get lower 13 bits
				print("TTL                    :\t",ip_hdr[5])
				print("Protocol               :\t",ip_hdr[6])
				print("Header Checksum        :\t",ip_hdr[7])
				print("Source IP              :\t",socket.inet_ntoa(ip_hdr[8]))
				print("Destination IP         :\t",socket.inet_ntoa(ip_hdr[9]))

				if ip_hdr[6]==1:
					print('--------------------------ICMP-------------------------')
					icmp_length = 4
					icmp_header = pkt[0][34:38]
					icmp_hdr=struct.unpack('!BBH', icmp_header)

					print("ICMP Type               :\t",icmp_hdr[0])
					print("ICMP Code               :\t",icmp_hdr[1])
					print("Checksum                :\t", icmp_hdr[2])

					print('\n-------------------------DATA--------------------------')
					print(pkt[0][34+icmp_length:])
					print("\n")

				elif ip_hdr[6]==17:
					print('--------------------------UDP--------------------------')
					udp_length = 8
					udp_header = pkt[0][34:42]
					udp_hdr=struct.unpack('!HHHH' , udp_header)
					print("Source_Port             :\t",udp_hdr[0])
					print("Destination Port        :\t", udp_hdr[1])
					print("Length                  :\t",udp_hdr[2])
					print("Checksum                :\t",udp_hdr[3])

					print('\n-------------------------DATA--------------------------')
					print(pkt[0][34+udp_length:])
					print("\n")


				else:			#Protocol==6(TCP)
					print('--------------------------TCP--------------------------')
					tcpheader=pkt[0][34:54]
					tcp_hdr=struct.unpack('!HHLLBBHHH',tcpheader)
					doff_reserved = tcp_hdr[4]
					tcp_length=doff_reserved >> 4
					print("Source Port            :\t",tcp_hdr[0])
					print("Destination Port       :\t",tcp_hdr[1])
					print("Sequence Number        :\t",tcp_hdr[2])
					print("Acknowledgement        :\t",tcp_hdr[3])
					print("TCP Header Length      :\t",(tcp_hdr[4]>>4)*4)
					print("Flag                   :\t",tcp_hdr[5])
					print("Window Size            :\t",tcp_hdr[6])
					print("TCP Checksum           :\t",tcp_hdr[7])
					print("Urgent Pointer         :\t",tcp_hdr[8])

					print('\n-------------------------DATA--------------------------')
					p=pkt[0][54:].split(b"\r\n")
					for info in p:
						if info !=  b"":
							print(info)
					print("\n")


				if binascii.hexlify(eth[0]) not in d:d[binascii.hexlify(eth[0]).decode("utf-8")]=socket.inet_ntoa(ip_hdr[9])
				if binascii.hexlify(eth[1]) not in d:d[binascii.hexlify(eth[1]).decode("utf-8")]=socket.inet_ntoa(ip_hdr[8])


			except(struct.error,TypeError):
				print("[Exception Unpacking...]\n")
				print("[Unpack Error]\t | \t [Protocol: %s]\n"%(ip_hdr[6]))
				print(pkt)
				print("\n\n")
				pass

	except KeyboardInterrupt:
		print('\n\n=======================MAC Table=======================')
		print("\n")
		print("MAC Address	        #	        IP Address")
		print("="*55)

		for key in d: print(':'.join(re.findall('..', key)),"    \t:    \t",d[key])
		print("\n\n")
		print("Exiting Program...")
		sys.exit()






###############################################################
#Hardware type							   ##	protocol type #
###############################################################
#h/w addr length #	protocol addr length   ##	opcode		  #
###############################################################
#					 source hardware addr					  #
###############################################################
#					 source protocol addr					  #
###############################################################
#					 destination hardware addr				  #
###############################################################
#					 destination protocol addr				  #
###############################################################
