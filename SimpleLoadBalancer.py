from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import pox.log.color


IDLE_TIMEOUT = 10
LOADBALANCER_MAC = EthAddr("00:00:00:00:00:FE")
ETHERNET_BROADCAST_ADDRESS=EthAddr("ff:ff:ff:ff:ff:ff")

class SimpleLoadBalancer(object):

	def __init__(self, service_ip, server_ips = []):
		core.openflow.addListeners(self)
		self.SERVERS = {} # IPAddr(SERVER_IP)]={'server_mac':EthAddr(SERVER_MAC),'port': PORT_TO_SERVER}
		self.CLIENTS = {}
		self.LOADBALANCER_MAP = {} # Mapping between clients and servers
		self.LOADBALANCER_IP = service_ip
		self.SERVER_IPS = server_ips
		self.ROBIN_COUNT = 0

	def _handle_ConnectionUp(self, event):
		self.connection = event.connection
		log.debug("FUNCTION: _handle_ConnectionUp")
		for ip in self.SERVER_IPS:
			selected_server_ip = ip
			self.send_arp_request(self.connection, selected_server_ip)
		log.debug("Sent ARP Requests to all servers")

	def round_robin(self):
		log.debug("FUNCTION: round_robin")
		a = self.SERVERS.keys()
		if self.ROBIN_COUNT == len(self.SERVER_IPS):
			self.ROBIN_COUNT = 0
		server = a[self.ROBIN_COUNT]
		self.ROBIN_COUNT += 1
		log.info("Round robin selected: %s" % server)
		return server

	def update_lb_mapping(self, client_ip):
		log.debug("FUNCTION: update_lb_mapping")
		if client_ip in self.CLIENTS.keys():
			if client_ip not in self.LOADBALANCER_MAP.keys():
				selected_server = self.round_robin()
				log.info("Server selected %s "%selected_server)
				self.LOADBALANCER_MAP[client_ip]=selected_server


	def send_arp_reply(self, packet, connection, outport):
		log.debug("FUNCTION: send_arp_reply")

                # Create an ARP reply
		arp_rep= arp()
		arp_rep.hwtype = arp_rep.HW_TYPE_ETHERNET
		arp_rep.prototype = arp_rep.PROTO_TYPE_IP
		arp_rep.hwlen = 6
		arp_rep.protolen = arp_rep.protolen
		arp_rep.opcode = arp_rep.REPLY
                
                # Set MAC destination and source
		arp_rep.hwdst = packet.src 
		arp_rep.hwsrc = LOADBALANCER_MAC 

		#Reverse the src, dest to have an answer. Set IP source and destination
		arp_rep.protosrc = packet.payload.protodst
		arp_rep.protodst = packet.payload.protosrc

		# Create ethernet frame, set packet type, dst, src
		eth = ethernet()
		eth.type = ethernet.ARP_TYPE 
		eth.dst = packet.src 
		eth.src = LOADBALANCER_MAC 
		eth.set_payload(arp_rep)
		
		# Create the necessary Openflow Message to make the switch send the ARP Reply
		msg = of.ofp_packet_out()
		msg.data = eth.pack()
		
		# Append the output port which the packet should be forwarded to.
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.in_port = outport
		connection.send(msg)


	def send_arp_request(self, connection, ip):

		log.debug("FUNCTION: send_arp_request")

		arp_req = arp()
		arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
		arp_req.prototype = arp_req.PROTO_TYPE_IP
		arp_req.hwlen = 6
		arp_req.protolen = arp_req.protolen
		arp_req.opcode = arp_req.REQUEST # Set the opcode
		
		arp_req.protodst = ip # IP the load balancer is looking for
		arp_req.hwsrc = LOADBALANCER_MAC # Set the MAC source of the ARP REQUEST
		arp_req.hwdst = ETHERNET_BROADCAST_ADDRESS # Set the MAC address in such a way that the packet is marked as a Broadcast
		arp_req.protosrc = self.LOADBALANCER_IP # Set the IP source of the ARP REQUEST

		eth = ethernet()
		eth.type = ethernet.ARP_TYPE 
		# eth.src =LOADBALANCER_MAC
		eth.dst = ETHERNET_BROADCAST_ADDRESS 
		eth.set_payload(arp_req)

		msg = of.ofp_packet_out() 
		msg.data = eth.pack()
		msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST,ip))
                
                # Append an action to the message which makes the switch flood the packet out
		msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
		connection.send(msg)
		


	def install_flow_rule_client_to_server(self,event, connection, outport, client_ip, server_ip):
		log.debug("FUNCTION: install_flow_rule_client_to_server")
		self.install_flow_rule_server_to_client(connection, event.port, server_ip,client_ip)

                # Create an instance of the type of Openflow packet you need to install flow table entries
		msg = of.ofp_flow_mod()
		msg.idle_timeout = IDLE_TIMEOUT

		msg.match.dl_type=ethernet.IP_TYPE
		
		# MATCH on destination and source IP
		msg.match.nw_src = client_ip
		msg.match.nw_dst = self.LOADBALANCER_IP
		
		# SET dl_addr source and destination addresses
		msg.actions.append(of.ofp_action_dl_addr.set_dst(self.SERVERS[server_ip].get('server_mac')))
		msg.actions.append(of.ofp_action_dl_addr.set_src(LOADBALANCER_MAC))
		
		# SET nw_addr source and destination addresses
		msg.actions.append(of.ofp_action_nw_addr.set_src(client_ip))
		msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
		
		# Set Port to send matching packets out
		msg.actions.append(of.ofp_action_output(port=outport))

		self.connection.send(msg)
		log.info("Installed flow rule: %s -> %s" % (client_ip,server_ip))
		
	def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip):
		log.debug("FUNCTION: install_flow_rule_server_to_client")
                
                # Create an instance of the type of Openflow packet you need to install flow table entries
		msg = of.ofp_flow_mod()
		msg.idle_timeout = IDLE_TIMEOUT

		msg.match.dl_type=ethernet.IP_TYPE
		
		# MATCH on destination and source IP
		msg.match.nw_src = server_ip
		msg.match.nw_dst = client_ip
		
		# SET dl_addr source and destination addresses
		msg.actions.append(of.ofp_action_dl_addr.set_dst(self.CLIENTS[client_ip].get('client_mac')))
		msg.actions.append(of.ofp_action_dl_addr.set_src(LOADBALANCER_MAC))
		
		# SET nw_addr source and destination addresses
		msg.actions.append(of.ofp_action_nw_addr.set_src(self.LOADBALANCER_IP))
		msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
		
		# Set Port to send matching packets out
		msg.actions.append(of.ofp_action_output(port=outport))
		self.connection.send(msg)
		log.info("Installed flow rule: %s -> %s" % (server_ip,client_ip))

	def _handle_PacketIn(self, event):
		log.debug("FUNCTION: _handle_PacketIn")
		packet = event.parsed
		connection = event.connection
		inport = event.port
		if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
			log.info("Received LLDP or IPv6 Packet...")
                
    # Handle ARP Packets
		elif packet.type == packet.ARP_TYPE: 
			log.debug("Received ARP Packet")
			response = packet.payload
			
			# Handle ARP replies
			if response.opcode == response.REPLY: 
				log.debug("ARP REPLY Received")
				if response.protosrc not in self.SERVERS.keys():
          # Add Servers MAC and port to SERVERS dict
					self.SERVERS[IPAddr(response.protosrc)] = {'server_mac':EthAddr(packet.payload.hwsrc), 'port': inport}
                        
    # Handle ARP requests
			elif response.opcode == response.REQUEST: 
				log.debug("ARP REQUEST Received")
				if response.protosrc not in self.SERVERS.keys() and response.protosrc not in self.CLIENTS.keys():
        #Insert client's ip  mac and port to a forwarding table
					self.CLIENTS[response.protosrc]={'client_mac':EthAddr(packet.payload.hwsrc),'port':inport}		
									
				if (response.protosrc in self.CLIENTS.keys()and response.protodst == self.LOADBALANCER_IP):
					log.info("Client %s sent ARP req to LB %s"%(response.protosrc,response.protodst))
					# Load Balancer intercepts ARP Client -> Server
					# Send ARP Reply to the client, include the event.connection object
					self.send_arp_reply(packet, connection, inport)
				
				elif response.protosrc in self.SERVERS.keys() and response.protodst in self.CLIENTS.keys():
					log.info("Server %s sent ARP req to client"%response.protosrc)
					
					# Load Balancer intercepts ARP from Client <- Server
					# Send ARP Reply to the Server, include the event.connection object
					self.send_arp_reply(packet, connection, inport)
				else:
					log.info("Invalid ARP request")
                
                # Handle IP Packets
		elif packet.type == packet.IP_TYPE: 
			log.debug("Received IP Packet from %s" % packet.next.srcip)
			# Handle Requests from Clients to Servers
			# Install flow rule Client -> Server
			# Check if the packet is destined for the LB and the source is not a server :
			if (packet.next.dstip == self.LOADBALANCER_IP and packet.next.srcip not in self.SERVERS.keys()):
				self.update_lb_mapping(packet.next.srcip)
				
				# Get client IP from the packet
				client_ip = packet.payload.srcip 
				server_ip = self.LOADBALANCER_MAP.get(packet.next.srcip)
				
				# Get Port of Server
				outport =  int(self.SERVERS[server_ip].get('port'))

				self.install_flow_rule_client_to_server(event,connection, outport, client_ip,server_ip)
								
				eth = ethernet()
				eth.type = ethernet.IP_TYPE
				eth.src = LOADBALANCER_MAC
				eth.dst = self.SERVERS[server_ip].get('server_mac')
				eth.set_payload(packet.next)

				# Send the first packet (which was sent to the controller from the switch)
				# to the chosen server, so there is no packetloss
				msg= of.ofp_packet_out()
				msg.data = eth.pack()
				msg.in_port = inport
				
				# Add an action which sets the MAC source to the LB's MAC
				msg.actions.append(of.ofp_action_dl_addr.set_src(LOADBALANCER_MAC))
				# Add an action which sets the MAC destination to the intended destination...
				msg.actions.append(of.ofp_action_dl_addr.set_dst(self.SERVERS[server_ip].get('server_mac')))

				# Add an action which sets the IP source
				msg.actions.append((of.ofp_action_nw_addr.set_src(client_ip)))
				# Add an action which sets the IP destination
				msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
				# Add an action which sets the Outport
				msg.actions.append(of.ofp_action_output(port=outport))

				connection.send(msg)

			# Handle traffic from Server to Client
			# Install flow rule Client <- Server
			elif packet.next.dstip in self.CLIENTS.keys(): 
				log.info("Installing flow rule from Server -> Client")
				if packet.next.srcip in self.SERVERS.keys():
                                        # Get the source IP from the IP Packet
					server_ip = packet.next.srcip 

					client_ip = self.LOADBALANCER_MAP.keys()[list(self.LOADBALANCER_MAP.values()).index(packet.next.srcip)]
					outport=int(self.CLIENTS[client_ip].get('port'))
					self.install_flow_rule_server_to_client(connection, outport, server_ip,client_ip)
	
					eth = ethernet()
					eth.type =  ethernet.IP_TYPE
					eth.src = LOADBALANCER_MAC 
					eth.dst = self.CLIENTS[client_ip].get('client_mac') 
					eth.set_payload(packet.next)
					

					# Send the first packet (which was sent to the controller from the switch)
					# to the chosen server, so there is no packetloss
					msg = of.ofp_packet_out() 
					msg.data = eth.pack()
					msg.in_port = inport 

					# Add an action which sets the MAC source to the LB's MAC
					msg.actions.append(of.ofp_action_dl_addr.set_src(LOADBALANCER_MAC))
					# Add an action which sets the MAC destination to the intended destination...
					msg.actions.append(of.ofp_action_dl_addr.set_dst(self.CLIENTS[client_ip].get('client_mac')))

					# Add an action which sets the IP source
					msg.actions.append(of.ofp_action_nw_addr.set_src(self.LOADBALANCER_IP)) 
					# Add an action which sets the IP destination
					msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
					# Add an action which sets the Outport
					msg.actions.append(of.ofp_action_output(port=outport))
		
					self.connection.send(msg)

		
		else:
			log.info("Unknown Packet type: %s" % packet.type)
			return

		return

def launch(loadbalancer, servers):
	# Color-coding and pretty-printing the log output
	pox.log.color.launch()
	pox.log.launch(format="[@@@bold@@@level%(name)-23s@@@reset] " +
						  "@@@bold%(message)s@@@normal")
	log.info("Loading Simple Load Balancer module:\n\n-----------------------------------CONFIG----------------------------------\n")
	server_ips = servers.replace(","," ").split()
	server_ips = [IPAddr(x) for x in server_ips]
	loadbalancer_ip = IPAddr(loadbalancer)
	log.info("Loadbalancer IP: %s" % loadbalancer_ip)
	log.info("Backend Server IPs: %s\n\n---------------------------------------\n\n" % ', '.join(str(ip) for ip in server_ips))
	core.registerNew(SimpleLoadBalancer, loadbalancer_ip, server_ips)