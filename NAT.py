# Copyright (C) 2014 SDN Hub
#
# Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
# You may not use this file except in compliance with this License.
# You may obtain a copy of the License at
#
#    http://www.gnu.org/licenses/gpl-3.0.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.


from pox.core import core
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
from pox.lib.revent import EventContinue,EventHalt
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.openflow.discovery import Discovery
from pox.openflow.topology import Topology
import sys
import random
import copy

log = core.getLogger()

############## Global constants #############

virtual_ip = IPAddr("10.0.0.5")
virtual_mac = EthAddr("00:00:00:00:00:05")

server = {'ip':IPAddr("10.0.0.4"), 'mac':EthAddr("00:00:00:00:00:04"), 'outport': 4}

router = {'ip_public': virtual_ip, 'mac': virtual_mac} 

################ Handlers ###################

def _handle_PacketIn (event):
    global server_index 
    global counter
    global total_servers
    packet = event.parsed

    # Only handle IPv4 flows
    if (not event.parsed.find("ipv4")):
        return EventContinue
        
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    
    if (msg.match.nw_src == server['ip']):
        return EventContinue
            
    # Setup route to server
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    
    # create copy of private ip, private mac and private port
    ip_private = copy.copy(msg.match.nw_src)
    mac_private = copy.copy(msg.match.dl_src)
    port_private = copy.copy(msg.match.tp_src)
    
    msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, router['mac']))
    msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_SRC, router['ip_public']))
    msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, server['mac']))
    msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, server['ip']))
    msg.actions.append(of.ofp_action_output(port = server['outport']))
    event.connection.send(msg)
    
    
    # Setup reverse route from server
    reverse_msg = of.ofp_flow_mod()
    reverse_msg.buffer_id = None
    reverse_msg.in_port = server['outport']

    reverse_msg.match = of.ofp_match()
    reverse_msg.match.dl_src = server['mac']
    reverse_msg.match.nw_src = server['ip']
    
    reverse_msg.match.tp_src = msg.match.tp_dst
    
    reverse_msg.actions.append(of.ofp_action_tp_port(of.OFPAT_SET_TP_DST, port_private))
    reverse_msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, mac_private))
    reverse_msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, ip_private))
    reverse_msg.actions.append(of.ofp_action_output(port = msg.in_port))
    event.connection.send(reverse_msg)

    return EventHalt

def launch ():
    # To intercept packets before the learning switch
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn, priority=2)
    log.info("Stateless LB running.")