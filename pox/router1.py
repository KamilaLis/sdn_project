'''
sudo mn --custom mytopo_test.py --topo mytopo --mac --switch ovsk --controller remote,ip=192.168.56.1,port=6633
./pox.py log.level --DEBUG router1 samples.pretty_log openflow.discovery
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr
from pox.lib.recoco import Timer

log = core.getLogger()

FLOW_IDLE_TIMEOUT = 50
FLOW_HARD_TIMEOUT = 50

ip_to_subnet = {
  '10.0.1.100': ['10.0.1.0/24', '10.0.1.1'], 
  '10.0.2.100': ['10.0.2.0/24', '10.0.2.1']
}
ip_to_mac = {
  '10.0.1.100': '00:00:00:00:00:01', 
  '10.0.2.100': '00:00:00:00:00:02'
}

basic_ttl = 3
forever_ttl = 999

class Switch (object):
  """
  A Switch object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection, features):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.port_to_mac = {}
    self.ip_to_port = {
        # "10.0.1.1":1,
        # "10.0.2.1":2
    }
    self.routing_table = {
        # '10.0.1.0/24': ['10.0.1.100', 's1-eth1', '10.0.1.1', 1, '00:00:00:00:00:01',1], 
        # '10.0.2.0/24': ['10.0.2.100', 's1-eth2', '10.0.2.1', 2, '00:00:00:00:00:02',1]
    }
    self.port_to_hwaddr = {}
    for port in features.ports:
        self.port_to_hwaddr[port.port_no] =  port.hw_addr.toStr()
        # self.routing_table[port.port_no] = [port.name]

    # log.debug("%s %d \t%s %d" % (features.ports[0].name, features.ports[0].port_no,
    #                             features.ports[1].name,features.ports[1].port_no))
    Timer(2, self.broadcast_routing_table, recurring = True)


  def broadcast_routing_table(self):
    rip_msg = pkt.rip()
    rip_msg.version = 2
    rip_msg.command = pkt.RIP_RESPONSE
    for entry in self.routing_table:
      rip_entry = pkt.RIPEntry()
      rip_entry.ip = adr.IPAddr(entry.split("/")[0])
      rip_entry.netmask = int(entry.split("/")[1])
      rip_entry.metric = self.routing_table[entry][-1]
      rip_msg.entries.append(rip_entry)
      if entry[1] != forever_ttl:
        --self.routing_table[entry][1]
        if self.routing_table[entry][1]==0:
          del self.routing_table[entry]

    udp = pkt.udp()
    udp.srcport = 520
    udp.dstport = 520
    # log.debug( "Created rip msg of len: %d", len(rip_msg) )
    udp.len = len(rip_msg)
    udp.payload = rip_msg

    ipv4 = pkt.ipv4()
    ipv4.protocol = pkt.ipv4.UDP_PROTOCOL
    ipv4.srcip = pkt.IP_ANY
    ipv4.dstip = pkt.rip.RIP2_ADDRESS
    ipv4.payload = udp

    ether = pkt.ethernet()
    ether.type = pkt.ethernet.IP_TYPE
    ether.dst = adr.EthAddr('ff:ff:ff:ff:ff:ff')
    ether.payload = ipv4
    for port in self.port_to_hwaddr.keys()[0:-1]:
      ether.src = self.port_to_hwaddr[port]
    
      # log.debug( "Broadcasting routing table" )

      msg = of.ofp_packet_out()
      msg.data = ether.pack()

      # Add an action to send to the specified port
      action = of.ofp_action_output(port = port)
      msg.actions.append(action)
      self.connection.send(msg)

  def FlowMode(self, packet_in, out_port):
    log.debug("Flow Mode install  Successfully")
    msg = of.ofp_flow_mod()
    msg.match.in_port = packet_in.in_port
    msg.idle_timeout = 240
    msg.buffer_id = packet_in.buffer_id
    msg.actions.append(of.ofp_action_output(port = out_port))     
  
  def act_like_router (self, packet, packet_in):
    #handle arp

    if packet.type == pkt.ethernet.IP_TYPE:
      ip_packet = packet.payload
      if ip_packet.protocol == pkt.ipv4.UDP_PROTOCOL:
        udp_packet = ip_packet.payload
        if udp_packet.dstport == 520:
          rip_packet = udp_packet.payload
          self.port_to_mac[packet_in.in_port] = packet.src
          # log.debug("got rip packet form port: %s", packet_in.in_port)
          for entry in rip_packet.entries:
            key = entry.ip.toStr()+'/'+str(entry.network_bits)
            if key in self.routing_table.keys():
              if self.routing_table[key][-1]-1 > entry.metric:
                self.routing_table[key][0] = packet_in.in_port
                self.routing_table[key][-1] = entry.metric+1
                self.routing_table[key][1] = basic_ttl
            else:
              self.routing_table[key] = [packet_in.in_port, basic_ttl,\
                                                                  entry.metric+1]
          return
    if packet.type == pkt.ethernet.ARP_TYPE:
        dst_ip = packet.payload.protodst.toStr() 
        if packet.payload.opcode == pkt.arp.REQUEST \
            and dst_ip.split(".")[3] == "1":
            log.debug("ARP request received")
            log.debug("%s, port: %d", dst_ip, packet_in.in_port)
            # self.ip_to_port[dst_ip] = packet_in.in_port
            # self.routing_table[packet_in.in_port].append([ \
            #                                     packet.payload.protosrc.toStr(),\
            #                                     packet.payload.hwsrc.toStr()])
            # log.debug("%s", packet.payload.protodst.toStr().split(".")[3])
            self.routing_table[ip_to_subnet[packet.payload.protosrc.toStr()][0]] = \
                          [packet_in.in_port, forever_ttl, 0]
            self.port_to_mac[packet_in.in_port] = packet.src
            print(self.port_to_mac)
            arp_reply = pkt.arp()
            arp_reply.hwsrc = adr.EthAddr(self.port_to_hwaddr[packet_in.in_port])
            arp_reply.hwdst = packet.payload.hwsrc
            arp_reply.opcode = pkt.arp.REPLY
            arp_reply.protosrc = packet.payload.protodst
            arp_reply.protodst = packet.payload.protosrc
            ether = pkt.ethernet()
            ether.type = pkt.ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = packet.dst
            ether.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = ether.pack()

                # Add an action to send to the specified port
            action = of.ofp_action_output(port = packet_in.in_port)
            msg.actions.append(action)
            #msg.in_port = event.port

            # Send message to switch
            self.connection.send(msg)
            print(self.routing_table)
            print(self.ip_to_port)
            print(self.port_to_hwaddr)
            log.debug("ARP reply sent")
        elif packet.payload.opcode == pkt.arp.REPLY:
            log.debug ("It's a reply!" )
            self.port_to_mac[packet_in.in_port] = packet.src
        else:
            log.debug( "Some other ARP opcode" )

    # elif packet.type == pkt.ethernet.IP_TYPE:
    #   ip_packet = packet.payload
    #     if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
    #         icmp_packet = ip_packet.payload
    #         if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
    #             log.debug("ICMP request received")
    #             src_ip = ip_packet.srcip
    #             dst_ip = ip_packet.dstip
    #             k = 0
    #             log.debug(self.routing_table.keys())
    #             for key in self.routing_table.keys():
    #                 if dst_ip.inNetwork(key):
    #                     k = key
    #                     break
    #             if k!=0:
    #                 log.debug("ICMP reply sent")
    #                 log.debug("network containing host: "+k)
    #                 ech = pkt.echo()
    #                 ech.seq = icmp_packet.payload.seq + 1
    #                 ech.id = icmp_packet.payload.id

    #                 icmp_reply = pkt.icmp()
    #                 icmp_reply.type = pkt.TYPE_ECHO_REPLY
    #                 icmp_reply.payload = ech
                    
    #                 ip_p = pkt.ipv4()
    #                 ip_p.srcip = dst_ip
    #                 ip_p.dstip = src_ip
    #                 ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
    #                 ip_p.payload = icmp_reply

    #                 eth_p = pkt.ethernet()
    #                 eth_p.type = pkt.ethernet.IP_TYPE
    #                 eth_p.dst = packet.src
    #                 eth_p.src = packet.dst
    #                 eth_p.payload = ip_p

    #                 msg = of.ofp_packet_out()
    #                 msg.data = eth_p.pack()

    #                 # Add an action to send to the specified port
    #                 action = of.ofp_action_output(port = packet_in.in_port)
    #                 #fl2.actions.append(action)
    #                 msg.actions.append(action)
    #                 #msg.in_port = event.port

    #                 # Send message to switch
    #                 self.connection.send(msg)
    #             else:
    #                 log.debug("ICMP destination unreachable")
    #                 unr = pkt.unreach()
    #                 unr.payload = ip_packet

    #                 icmp_reply = pkt.icmp()
    #                 icmp_reply.type = pkt.TYPE_DEST_UNREACH
    #                 icmp_reply.payload = unr
                    
    #                 ip_p = pkt.ipv4()
    #                 ip_p.srcip = dst_ip
    #                 ip_p.dstip = src_ip
    #                 ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
    #                 ip_p.payload = icmp_reply

    #                 eth_p = pkt.ethernet()
    #                 eth_p.type = pkt.ethernet.IP_TYPE
    #                 eth_p.dst = packet.src
    #                 eth_p.src = packet.dst
    #                 eth_p.payload = ip_p

    #                 msg = of.ofp_packet_out()
    #                 msg.data = eth_p.pack()

    #                 # Add an action to send to the specified port
    #                 action = of.ofp_action_output(port = packet_in.in_port)
    #                 #fl2.actions.append(action)
    #                 msg.actions.append(action)
    #                 #msg.in_port = event.port

    #                 # Send message to switch
    #                 self.connection.send(msg)
      # if ip_packet.protocol == pkt.ipv4.UDP_PROTOCOL:
      #   udp_packet = ip_packet.payload
      #   if udp_packet.dstport == 520:
      #     rip_packet = udp_packet.payload
      #     # log.debug("got rip packet form port: %s", packet_in.in_port)
      #     for entry in rip_packet.entries:
      #       key = entry.ip.toStr()+'/'+str(entry.network_bits)
      #       if key in self.routing_table.keys():
      #         if self.routing_table[key][-1]-1 > entry.metric:
      #           self.routing_table[key][0] = packet_in.in_port
      #           self.routing_table[key][-1] = entry.metric+1
      #           self.routing_table[key][1] = basic_ttl
      #       else:
      #         self.routing_table[key] = [packet_in.in_port, basic_ttl,\
      #                                                             entry.metric+1]

    else:
        src_ip = ip_packet.srcip
        dst_ip = ip_packet.dstip
    
        k = 0
        for key in self.routing_table.keys():
          if dst_ip.inNetwork(key):
            k = key
            break
        if k != 0:
          out_port = self.routing_table[k][0]
          print(out_port)
          print(k)
          print(self.routing_table)
          print(packet.dst)
          print(self.port_to_mac)
          print(self.port_to_mac[out_port])
          print(dst_ip)
          # packet.dst = adr.EthAddr(self.port_to_mac[out_port])
          # print(packet.dst)
          # msg = of.ofp_packet_out()
          match = of.ofp_match.from_packet(packet)
          action = of.ofp_action_output(port = out_port)
          msg = of.ofp_flow_mod()
          msg.match = match
          msg.match.in_port = packet_in.in_port
          # msg.out_port = out_port

          msg.idle_timeout = FLOW_IDLE_TIMEOUT
          msg.hard_timeout = FLOW_HARD_TIMEOUT
          # packet.src = packet.dst
          # packet.dst = dsteth
          # msg.data = packet.pack()
          msg.actions.append(of.ofp_action_dl_addr.set_dst(adr.EthAddr(self.port_to_mac[out_port])))
          msg.actions.append(action)
          self.connection.send(msg)
          # self.FlowMode( packet_in, packet_in.in_port)  
        else:
          log.debug("ICMP destination unreachable")
          unr = pkt.unreach()
          unr.payload = ip_packet

          icmp_reply = pkt.icmp()
          icmp_reply.type = pkt.TYPE_DEST_UNREACH
          icmp_reply.payload = unr
          
          ip_p = pkt.ipv4()
          ip_p.srcip = dst_ip
          ip_p.dstip = src_ip
          ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
          ip_p.payload = icmp_reply

          eth_p = pkt.ethernet()
          eth_p.type = pkt.ethernet.IP_TYPE
          eth_p.dst = packet.src
          eth_p.src = packet.dst
          eth_p.payload = ip_p

          msg = of.ofp_packet_out()
          msg.data = eth_p.pack()

          # Add an action to send to the specified port
          action = of.ofp_action_output(port = packet_in.in_port)
          #fl2.actions.append(action)
          msg.actions.append(action)
          #msg.in_port = event.port

          # Send message to switch
          self.connection.send(msg)       


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.act_like_router(packet, packet_in)


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Switch(event.connection, event.ofp)

  # def _handle_openflow_discovery_LinkEvent (self, event):
  #   log.debug("Controlling %s" % (event.connection,))

  core.openflow.addListenerByName("ConnectionUp", start_switch)
