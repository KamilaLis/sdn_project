"""
Detects topology and choose path based on Distance Vector Algorithm.

Requires discovery.

./pox.py forwarding.l2_learning\
 openflow.spanning_tree --no-flood --hold-down \
 log.level --DEBUG samples.pretty_log \
 openflow.discovery host_tracker \
 info.packet_dump
"""
# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
from pox.lib.util import dpid_to_str
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library

# Create a logger for this component
log = core.getLogger()

# Flow timeouts
FLOW_IDLE_TIMEOUT = 65535
FLOW_HARD_TIMEOUT = 3000

switches = {}      # [dpid] -> Switch
links = []         # [(dpid u, dpid v)]
                   # moze [(u,v,port)] ?
                   # albo [(end1,end2)], gdzie end[0] = (dpid1,port1)
linkToPort = {}    # [(dpid1, dpid2)] -> port1
macToPort = {}     # mac -> (Switch, port)


def calc_costs(vertices, edges, source):
    """
    Computes cost of paths from source to all entities in network.
    Essentially Bellman-Ford algorythm.
    """
    distance = {}
    predecessor = {}
    # Step 1: initialize graph
    for v in vertices:
        distance[v] = 16 # inf
        predecessor[v] = None
    distance[source] = 0
    # Step 2: relax edges repeatedly
    for i in range (1,len(vertices)-1): # dla wszystkich wezlow
        for e in edges: # (u,v)
            if distance[e[0]] + 1 < distance[e[1]]:
                distance[e[1]] = distance[e[0]] + 1
                predecessor[e[1]] = e[0]
    return distance, predecessor

def get_path(dst, predecessor):
    """
    Get full path to dst based on predecessor from calc_costs
    """
    path = [dst]
    while predecessor[dst]:
        path.append(predecessor[dst])
        dst = predecessor[dst]
    path.reverse()
    return path


class Switch(object):

    def __init__ (self, connection, dpid):
        self.connection = connection
        self.ports = connection.features.ports
        self.dpid = dpid
        self.distance = None
        self.predecessor = None

        connection.addListeners(self)

    def set_distances(self, switches, links):
        self.distance, self.predecessor = calc_costs(switches, links, self.dpid)

    def _install (self, in_port, out_port, match, buf = None):
        log.debug("Msgs installing params in_port:%s out_port:%s", in_port, out_port)
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.match.in_port = in_port
        msg.idle_timeout = FLOW_IDLE_TIMEOUT
        msg.hard_timeout = FLOW_HARD_TIMEOUT
        msg.actions.append(of.ofp_action_output(port = out_port))
        msg.buffer_id = buf
        self.connection.send(msg)

    def install_path(self, dst_sw, dst_port, match, event):
        """
        Install a path between this switch and some destination
        :param dst_sw       destination Switch object
        :param dst_port     
        """
        # p = _get_path(self, dst_sw, event.port, dst_port)
					   # src, dst, first_port, final_port
        log.debug("Installing path %s.%s", dst_sw.dpid, dst_port)

        if dst_sw.dpid == self.dpid:
            self._install(event.port, dst_port, match)
            return
        if not self.predecessor:
            self.set_distances(switches.keys(), links)

        path = get_path(dst_sw.dpid, self.predecessor)
        log.debug(path)
        # log.debug(self.predecessor)

        log.debug("Installing path for %s -> %s (%i hops)",
        self.dpid, dst_sw.dpid, len(path)-1)

        self._install(event.port, linkToPort[(self.dpid, path[1])], match)


    def _handle_PacketIn (self, event):
        def flood(message = None):
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)

        def drop(duration = None):
            if event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                event.ofp.buffer_id = None # Mark is dead
                msg.in_port = event.port
                self.connection.send(msg)

        packet = event.parsed

        loc = (self, event.port) # Place we saw this ethaddr
        oldloc = macToPort.get(packet.src) # Place we last saw this ethaddr

        if packet.effective_ethertype == packet.LLDP_TYPE:
            drop()
            return

        if oldloc is None:
            if packet.src.is_multicast == False:
                macToPort[packet.src] = loc # Learn position for ethaddr
                log.debug("Learned %s at %s.%i", packet.src, loc[0].dpid, loc[1])

        if packet.dst.is_multicast or packet.effective_ethertype == packet.ARP_TYPE:
            if packet.effective_ethertype != packet.ARP_TYPE:
                log.debug("Flood multicast from %s", packet.src)
            flood()
        else:
            if packet.dst not in macToPort:
                log.debug("%s unknown -- flooding" % (packet.dst,))
                flood()
            else:
                log.debug(packet.dst)
                dest = macToPort[packet.dst]
                match = of.ofp_match.from_packet(packet)
                self.install_path(dest[0], dest[1], match, event)


class PSIKTopo(object):
    """ Network topology. """
    def __init__ (self):
        core.listen_to_dependencies(self)

    def update_distances(self):
        """ Count new cost when topolog has changed. """
        if links:
            for s in switches.values():
                s.set_distances(switches.keys(), links)
            log.debug("Distances updated.")

    def _handle_openflow_ConnectionUp (self, event):
        s = dpid_to_str(event.dpid)
        if s not in switches.keys():
            switch = Switch(event.connection, s)
            log.debug("Connected %s" % (s,))
            switches[s] = switch
            # self.update_distances()

    def _handle_openflow_ConnectionDown (self, event):
        s = dpid_to_str(event.dpid)
        if s in switches.keys():
            log.debug("Disconnected %s" % (s,))
            del switches[s]
            # self.update_distances()

    def _handle_openflow_discovery_LinkEvent (self, event):
        s1 = event.link.dpid1 # The DPID of one of the switches involved in the link
        s2 = event.link.dpid2 # The DPID of the other switch involved in the link
        s1 = dpid_to_str(s1)
        s2 = dpid_to_str(s2)
        # if s1 > s2: s1,s2 = s2,s1

        assert s1 in switches
        assert s2 in switches

        if event.added and (s1,s2) not in links:
            links.append((s1,s2))
            linkToPort[(s1,s2)] = event.link.port1
            log.debug("Added link %s->%s" % (s1,s2))
        elif event.removed and (s1,s2) in links:
            links.remove((s1,s2))
            del linkToPort[(s1,s2)]
            log.debug("Removed link %s->%s" % (s1,s2))

def _go_up (event):
    # Event handler called when POX goes into up state
    log.info("PSIKTopo application is ready!")

@poxutil.eval_args
def launch ():
    if not core.hasComponent("PSIKTopo"):
        core.registerNew(PSIKTopo)

    core.addListenerByName("UpEvent", _go_up)
