from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3, ether
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.lib.packet import packet, ethernet, arp, lldp, icmpv6, udp , in_proto,ipv4,ether_types
import datetime, time, sys
from operator import attrgetter
import copy

flow_idle_timeout = 10 # idle timeout for the flow

class SamplePacket(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SamplePacket, self).__init__(*args, **kwargs)
        self.MAC_table = {}
        self.ARP_table = {}
        #
        self.Topology_db = {}
        self.network_changed_thread = None
        
        #
        self.datapaths = {}

        self.UDP_packet = {} 
        self.rcv_UDP = {}
        self.add_flow_udp = False
        
        self.sent_packet = {}
        
        self.isUpdate = False
        self.port_switch = {}
        self.switch_port_connect= []
        self.have_empty = False

        self.link_connection_switch = {} 
        self.port_out_group = []
        self.port_in_group = []
        self.action_group = []
        self.switch_drop = {} 

        self.estimate_link_loss= {}
        self.dem = 0
        self.index = 0
        self.mark_sample = False
        self.offset_send = {}
        self.offset_rcv = {}
        self.offset = {}
        self.stop_offset = False

        #
        self.port_host={}
        self.Switch_switch_db = {} 
        self.port_host_connect=[]
        self.learn_dict={}
        self.save_switch_request=[]
    
    # Add action for "missing flow"
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def action_for_missing_flow(self, ev):
        msg        = ev.msg
        dp         = msg.datapath
        ofp        = dp.ofproto
        ofp_parser = dp.ofproto_parser

        actions      = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        instructions = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        self.flow_add(dp, 0, 0, None, instructions)


    
    # Store and Map "Datapath" and "Datapath ID"
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def StateChange(self, ev):
        dp   = ev.datapath
        dpid = dp.id

        if ev.state == MAIN_DISPATCHER:
            self.datapaths.setdefault(dpid,dp)
            self.UDP_packet.setdefault(dpid,{})
            self.rcv_UDP.setdefault(dpid,{})
            self.offset_send.setdefault(dpid,[])
            self.offset_rcv.setdefault(dpid,[])

        if ev.state == DEAD_DISPATCHER:
            if (self.datapaths):
                self.datapaths.pop(dpid)
                self.UDP_packet.pop(dpid,{})
                self.rcv_UDP.pop(dpid,{})
                self.offset_send.pop(dpid,[])
                self.offset_rcv.pop(dpid,[])
    
    # Handle PACKET-IN message
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp  = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        buffer_id = msg.buffer_id

        pkt = packet.Packet(msg.data)
        etherh = pkt.get_protocol(ethernet.ethernet)   
        smac = etherh.src                               
        dmac = etherh.dst                              
        pin  = msg.match['in_port']                     
        pout = 0                                       
        dpid = dp.id                                    
        
       
        # Ignore LLDP, ICMPv6 packets

        if pkt.get_protocol(lldp.lldp) or pkt.get_protocol(icmpv6.icmpv6):
            return
        

        # Learn source MAC address and port

        self.MAC_table.setdefault(dpid,{})
        if (self.MAC_table[dpid].get(smac) != pin):
            self.MAC_table[dpid][smac] = pin
        # print("   - Updates MAC table: MAC={} <-> Port={}".format(smac,pin))
        #
        self.ARP_handle(dp, pin,smac,dmac,pkt,buffer_id)
       
        #Handle UDP packet

        if etherh.ethertype == ether_types.ETH_TYPE_IP:
            udp_packet = pkt.get_protocol(udp.udp)
            if udp_packet:
                udp_dst_port = udp_packet.dst_port
                
                if udp_dst_port ==  65534 and self.add_flow_udp == False:
                    if len(self.Topology_db.keys()) == 6:
                        self.monitor_thread = hub.spawn(self.PeriodReq)

                    for datapath in self.link_connection_switch.keys():
                        
                        if datapath in self.datapaths.keys():
                            dp = self.datapaths[datapath]
                            ofp_parser = dp.ofproto_parser
                            ofp = dp.ofproto
                            match_udp       =   ofp_parser.OFPMatch(eth_type=0x0800,ip_proto = in_proto.IPPROTO_UDP,udp_dst=udp_dst_port)
                            # Install the Flow Mod and Group Mod for the forwarding switch
                            if len(self.link_connection_switch[datapath]) < 2:    
                                actions_udp      = [ofp_parser.OFPActionOutput(self.link_connection_switch[datapath].values()[0][0])] 
                                instructions_udp    = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions_udp)]
                                self.flow_add(dp,0,2,match_udp,instructions_udp)
                                                               
                            else:
                                for next_switch in self.link_connection_switch[datapath]:
                                    port_out = self.link_connection_switch[datapath][next_switch][0]
                                    self.port_out_group.append(port_out)
                                    actions_gr = []
                                    
                                    if len(self.port_out_group) == len(self.link_connection_switch[datapath]):
                                        bucket = []      
                                        for i in range (len(self.port_out_group)):
                                            actions_gr.append([ofp_parser.OFPActionOutput(self.port_out_group[i])])
                                            bucket.append(ofp_parser.OFPBucket(actions=actions_gr[i]))

                                        req = ofp_parser.OFPGroupMod(dp, ofp.OFPGC_ADD,
                                                                ofp.OFPGT_ALL, 50, bucket)
                                        dp.send_msg(req)

                                        actions = [ofp_parser.OFPActionGroup(group_id=50)]
                                        instructions_udp =[ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                                        mod = ofp_parser.OFPFlowMod(datapath=dp, priority = 2,
                                                    match=match_udp, instructions = instructions_udp)
                                        dp.send_msg(mod)
                                        self.port_out_group=[]
                                
                                    
                    for dpid in self.switch_drop.keys():
                        if dpid in self.datapaths.keys():
                            dp = self.datapaths[dpid]
                            ofp_parser = dp.ofproto_parser
                            ofp = dp.ofproto 
                            if len(self.switch_drop[dpid]) < 2:
                                match_udp_drop       =   ofp_parser.OFPMatch(eth_type=0x0800,ip_proto = in_proto.IPPROTO_UDP
                                                         ,udp_dst=udp_dst_port,in_port=self.switch_drop[dpid].values()[0][0])
                                mod = ofp_parser.OFPFlowMod(datapath=dp, priority=3,idle_timeout = 40,
                                                            match=match_udp_drop)
                                dp.send_msg(mod)
                                
                            else:
                                for next_switch in self.switch_drop[dpid]:
                                    port_in = self.switch_drop[dpid][next_switch][0]
                                    self.port_in_group.append(port_in)
                                    if len(self.port_in_group) == len(self.switch_drop[dpid]):
                                        for i in range(len(self.port_in_group)):
                                            match_udp_drop_i =  ofp_parser.OFPMatch(eth_type=0x0800,ip_proto = in_proto.IPPROTO_UDP
                                                                        ,udp_dst=udp_dst_port,in_port=self.port_in_group[i])
                                            mod = ofp_parser.OFPFlowMod(datapath=dp, priority=3,idle_timeout = 40,
                                                            match=match_udp_drop_i)
                                            dp.send_msg(mod)
                                        self.port_in_group=[]

                    self.add_flow_udp = True


                      
                if udp_dst_port == 65535:
                    self.dem = 0

                    for dpid in self.link_connection_switch.keys():
                        if dpid in self.datapaths.keys():
                            dp = self.datapaths[dpid]
                            ofp_parser = dp.ofproto_parser
                            ofp = dp.ofproto
                            if len(self.link_connection_switch[dpid]) == 1:    
                                FlowStats_req = ofp_parser.OFPFlowStatsRequest(datapath= dp)
                                dp.send_msg(FlowStats_req)
                            else:
                                GroupStats_req = ofp_parser.OFPGroupStatsRequest(datapath=dp,flags = 0,group_id=50)
                                dp.send_msg(GroupStats_req)

                                hub.sleep(0.1) 
                                group_delete = ofp_parser.OFPGroupMod(dp,ofp.OFPGC_DELETE,
                                                                        ofp.OFPGT_ALL,50,None)
                                dp.send_msg(group_delete)
                    for dpid in self.switch_drop.keys():
                        if dpid in self.datapaths.keys():
                            dp = self.datapaths[dpid]
                            ofp_parser = dp.ofproto_parser
                            ofp = dp.ofproto    
                            FlowStats_req = ofp_parser.OFPFlowStatsRequest(datapath= dp)
                            dp.send_msg(FlowStats_req)
        
        
    def ARP_handle(self, a_dp, a_pin, a_smac, a_dmac, a_pkt, a_buffer):
        a_dpid = a_dp.id
        a_ofp  =  a_dp.ofproto
        a_ofp_parser  =  a_dp.ofproto_parser

        arp_pkt=a_pkt.get_protocol(arp.arp)
        if arp_pkt:
            _sip = arp_pkt.src_ip
            _dip = arp_pkt.dst_ip
            # Handle ARP request message
            if arp_pkt.opcode == arp.ARP_REQUEST:
                print ("   - Receives a ARP request packet from host {} ({}) aksing the MAC of {}". format(_sip,a_smac,_dip))
                
                # Update ARP table
                self.ARP_table.setdefault(a_dpid,{})
                if (self.ARP_table[a_dpid].get(a_smac) !=  _dip):
                    self.ARP_table[a_dpid][a_smac] = _sip
                    self.save_switch_request.append(a_dpid)
                    
                    #
                    for _dpid in self.ARP_table.keys():
                        if _dip in self.ARP_table[_dpid].values():
                            for _dmac in self.ARP_table[_dpid].keys():
                                if self.ARP_table[_dpid][_dmac] ==   _dip:
                                    
                                   
                                    e = ethernet.ethernet(dst=a_smac,src=_dmac,ethertype=ether.ETH_TYPE_ARP)
                                    a = arp.arp ( hwtype=1,proto=0x0800,hlen=6,plen=4,opcode=2,    
                                                    src_mac=_dmac, src_ip=_dip,
                                                    dst_mac=a_smac, dst_ip=_sip)

                                    p=packet.Packet()
                                    p.add_protocol(e)
                                    p.add_protocol(a)
                                    p.serialize()
                            
                                    actions = [a_ofp_parser.OFPActionOutput(a_pin)]
                                    self.send_packet(a_dp,a_ofp.OFP_NO_BUFFER,a_ofp.OFPP_CONTROLLER,actions,p.data)
                                
                                    break

                        if _dip not in self.ARP_table[_dpid].values():
                            self.ARP_MAC_not_in_table(a_dpid,a_smac,_sip,_dip,a_pin)
                                  
    
    # Handle ARP reply message
    
            if arp_pkt.opcode == arp.ARP_REPLY:
                print ("   - Receives a ARP reply packet from host {} ({}) answering the MAC of {}". format(_sip,a_smac,_dip))
                # Update ARP table
                self.ARP_table.setdefault(a_dpid,{})
                if (self.ARP_table[a_dpid].get(a_smac) != _sip):
                    self.ARP_table[a_dpid][a_smac]    =   _sip
                    # print("      + Update ARP table: MAC={} <--> IPv4={}".format(a_smac,_sip))

                # Insert Route if the destination Host and Source Host lie in different subnet.
                
                for datapath_id in self.ARP_table.keys():
                    if _dip in self.ARP_table[datapath_id].values():

                        for dp_id in self.ARP_table.keys():
                            if _sip in self.ARP_table[dp_id].values():

                                if _dip.split('.')[2] != _sip.split('.')[2]:
                                    dpid_dest = self.Get_dst_dpid(a_dmac)
                        
                                    path_route = self.FindRoute(a_dpid,dpid_dest)
                                    print(path_route)
                                   
                                    for i in range(len(path_route)):
                                        _dp         = self.datapaths[path_route[i]]
                                        _ofp        = _dp.ofproto
                                        _ofp_parser = _dp.ofproto_parser

                                        if i < len(path_route) - 1 :
                                            _pout = self.Get_port_out(path_route[i],path_route[i+1],a_dmac)
                                        else:
                                            _pout = self.MAC_table[path_route[i]][a_dmac]
                                        if i == 0:
                                            _pin = a_pin
                                            pout = _pout
                                        else: 
                                            _pin = self.Get_port_out(path_route[i],path_route[i-1], a_dmac)
                                        
                                        _actions = [_ofp_parser.OFPActionOutput(_pout)]
                                        _inst    = [_ofp_parser.OFPInstructionActions(_ofp.OFPIT_APPLY_ACTIONS, _actions)]
                                        _match   = _ofp_parser.OFPMatch(eth_dst=a_dmac, in_port=_pin)
                                        self.flow_add(_dp, 0, 1, _match, _inst)
                                    
                                        # Backward
                                        _actions = [_ofp_parser.OFPActionOutput(_pin)]
                                        _inst    = [_ofp_parser.OFPInstructionActions(_ofp.OFPIT_APPLY_ACTIONS, _actions)]
                                        _match   = _ofp_parser.OFPMatch(eth_dst=a_smac, in_port=_pout)
                                        self.flow_add(_dp, 0, 1, _match, _inst)
    
    
    def ARP_MAC_not_in_table(self,dpid,smac,sip,dip,ipin):
        p=packet.Packet()
        e=ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,src=smac,dst='FF:FF:FF:FF:FF:FF') # source MAC address cua h1, broadcast MAC address 
        a=arp.arp(hwtype=1,proto=0x0800,hlen=6,plen=4,opcode=1,
                    src_mac=smac,src_ip=sip,
                    dst_mac='FF:FF:FF:FF:FF:FF',dst_ip=dip)

        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
    
        for dp in list(self.datapaths.values()):
            if dp.id in list(self.port_host.keys()) and dp.id == int(dip.split('.')[2]):
                ofp = dp.ofproto
                ofp_parser = dp.ofproto_parser
                for port in list(self.port_host[dp.id]):
                    outport = port
                    actions = [ofp_parser.OFPActionOutput(outport)]
                    self.send_packet(dp, 0, ofp.OFPP_CONTROLLER, actions, p.data)

        
        
    # Flow Stats Reply Handler
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handle(self, ev):
        self.have_empty = False
        msg  = ev.msg
        body = msg.body
        dp   = msg.datapath
        dpid = dp.id
        if self.stop_offset == False:
            self.offset_rcv[dpid].append(time.time())

        for stat in sorted([flow for flow in body if flow.priority == 2],
                           key=lambda flow: (flow.match['udp_dst'])):
            
            if ev.msg.datapath.id in self.UDP_packet.keys():
                self.UDP_packet[dpid][stat.instructions[0].actions[0].port]=stat.packet_count

        for stat in sorted([flow for flow in body if flow.priority == 3],
                           key=lambda flow: (flow.match['in_port'])):
            
            if ev.msg.datapath.id in self.UDP_packet.keys():
                self.UDP_packet[dpid][stat.match['in_port']]=stat.packet_count

        n_switches = self.num_switches()

        for dp in self.UDP_packet.values():
            if len(dp) == 0:
                self.have_empty = True
        if self.have_empty == False:
            self.filter_switch_for_UDP_packet()
    

    # Group Stats Reply handling
    
    @set_ev_cls(ofp_event.EventOFPGroupStatsReply, MAIN_DISPATCHER)
    def groups_stats_reply_handle(self, ev):
        self.have_empty = False
        msg  = ev.msg
        body = msg.body
        dp   = msg.datapath
        dpid = dp.id
        groups = ev.msg.body
        if self.stop_offset == False:
            self.offset_rcv[dpid].append(time.time())
        
        for stat in groups:
            if ev.msg.datapath.id in self.UDP_packet.keys():
                if ev.msg.datapath.id in self.link_connection_switch.keys():
                    for switch in self.link_connection_switch[dpid]:
                            self.UDP_packet[dpid][self.link_connection_switch[dpid][switch][0]]= stat.packet_count
        n_switches = self.num_switches()

        for dp in self.UDP_packet.values():
            if len(dp) == 0:
                self.have_empty = True
        if self.have_empty == False:
            self.filter_switch_for_UDP_packet()
    
    # Change the switch connection from dst_port in self.UDP_packet()
    
    def filter_switch_for_UDP_packet(self):
     
        self.dem = self.dem + 1
        
        if len(self.rcv_UDP[1].values()) == 0:
            for dpid in self.UDP_packet.keys():
                self.sent_packet.setdefault(dpid,{})
                if dpid in self.Topology_db.keys():
                    for next_switch in self.Topology_db[dpid]:
                        for port in self.UDP_packet[dpid]:
                            if port == self.Topology_db[dpid][next_switch][0]:
                                save = self.UDP_packet[dpid][port]
                                self.sent_packet[dpid][next_switch] = save
            self.Estimate()

        elif self.dem == len(self.datapaths.keys()):
            for dpid in self.UDP_packet.keys():
                self.sent_packet.setdefault(dpid,{})
                if dpid in self.Topology_db.keys():
                    for next_switch in self.Topology_db[dpid]:
                        for port in self.UDP_packet[dpid]:
                            if port == self.Topology_db[dpid][next_switch][0]:
                                save = self.UDP_packet[dpid][port] - self.rcv_UDP[dpid][port]
                                self.sent_packet[dpid][next_switch] = save
            self.Estimate()

    #Estimate Link Loss rate
    
    def Estimate(self):
        self.dem = 0
        print("")
        print("<< Received Probe Packet ---> Start estimating >>") 
        print("")
        self.rcv_UDP.clear()
        self.rcv_UDP = copy.deepcopy(self.UDP_packet)
       
        self.estimate_link_loss = copy.deepcopy(self.link_connection_switch)
        # print("Packet sent: {}".format(self.sent_packet))
        for dpid in self.link_connection_switch.keys(): 
            for next_switch in self.link_connection_switch[dpid]: 
                if dpid in self.sent_packet.keys(): 
                    for dp_id in self.sent_packet.keys(): 
                            if all(self.sent_packet[dp_id].values()): 
                                if dp_id == next_switch: 
                                   for target_switch in self.sent_packet[dp_id]: 
                                        next_sw = self.sent_packet[dpid][next_switch]
                                        target_sw = self.sent_packet[dp_id][target_switch]
                                        
                                        if target_switch != dpid: 
                                            self.estimate_link_loss[dpid][next_switch] = round(float(float(abs(next_sw - target_sw))/float(next_sw)),4)
                                        
                                        else: 
                                            self.estimate_link_loss[dpid][next_switch]= round(float(float(abs(next_sw - target_sw))/float(next_sw )),4)
                            else: 
                                if dp_id == next_switch:
                                    for target_switch in self.sent_packet[dp_id]: 
                                        if target_switch == dpid:
                                            
                                            self.estimate_link_loss[dpid][next_switch]= round(float(float(abs(next_sw - target_sw))/float(next_sw)),4)
        
        if self.mark_sample == False:

            print("")
            print("Packet sent: {}".format(self.sent_packet))
            print("")
            print("\n Estimate Link Loss: {}".format(self.estimate_link_loss))
            
            for dpid in self.estimate_link_loss.keys():
                for sw,result in self.estimate_link_loss[dpid].items():
                    print ("Link {} to {}: r={}".format(dpid,sw,result))

        if len(self.estimate_link_loss.keys()) == 4 and self.stop_offset == False:
            print("-------------------------------------------------------------------------------------------")
            print(self.offset_send)
            print("")
            print(self.offset_rcv)
            print("-------------------------------------------------------------------------------------------")
            for id in self.Topology_db.keys():
                self.offset[id] = self.offset_rcv[id][0] - self.offset_send[id][0]
                print("Time offset of sw [{}] is --- {}".format(id, self.offset[id]*1000))
            self.stop_offset = True

    def PeriodReq (self):
        
        while 1:
            print("Waiting for 45s ...")
            self.ShowWaitingTime(45)
            self.mark_sample = True
            self.send_flowstat()

            print("Sample packet in 5 seconds")
            self.ShowWaitingTime(5)
            self.mark_sample = False
            self.send_flowstat()
            


    def send_flowstat(self):
        for dpid in self.link_connection_switch.keys():
                if dpid in self.datapaths.keys():
                    dp = self.datapaths[dpid]
                    ofp_parser = dp.ofproto_parser
                    ofp = dp.ofproto
                    if len(self.link_connection_switch[dpid]) == 1:    
                        FlowStats_req = ofp_parser.OFPFlowStatsRequest(datapath= dp)
                        dp.send_msg(FlowStats_req)
                    else:
                        GroupStats_req = ofp_parser.OFPGroupStatsRequest(datapath=dp,flags = 0,group_id=50)
                        dp.send_msg(GroupStats_req)
                    if self.stop_offset == False:
                        self.offset_send[dpid].append(time.time())

        for dpid in self.switch_drop.keys():
            if dpid in self.datapaths.keys():
                dp = self.datapaths[dpid]
                ofp_parser = dp.ofproto_parser
                ofp = dp.ofproto    
                FlowStats_req = ofp_parser.OFPFlowStatsRequest(datapath= dp)
                dp.send_msg(FlowStats_req)

                if self.stop_offset == False:
                    self.offset_send[dpid].append(time.time())


    def ShowWaitingTime(self,sec):
        for remaining in range(sec, 0, -1):
            hub.sleep(1)
            sys.stdout.write("\r")
            _str = ["=" for sp in range(10-(remaining+9)%10)]
            sys.stdout.write("{:2d} seconds remaining {}>          ".format(remaining, "".join(_str)))
            sys.stdout.flush()



    def Get_dst_dpid(self, mac):
        for dpid in self.ARP_table.keys():
            if mac in self.ARP_table[dpid].keys():
                return dpid
        return
    
    # Port status changed

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)    
    def port_changed(self, ev):
        msg = ev.msg
        dp  = msg.datapath
        ofp = dp.ofproto

        reason  = msg.reason
        desc    = msg.desc
        port_no = desc.port_no

        if reason == ofp.OFPPR_ADD:
            reason_st = 'ADD'
        elif reason == ofp.OFPPR_DELETE:
            reason_st = 'DELETE'
        elif reason == ofp.OFPPR_MODIFY:
            reason_st = 'MODIFY'
        else:
            reason_st = 'UNKNOWN'
        
        if desc.state == ofp.OFPPS_LINK_DOWN:
            state = 'DOWN'
        elif desc.state == ofp.OFPPS_BLOCKED:
            state = 'BLOCKED'
        elif desc.state == ofp.OFPPS_LIVE:
            state = 'LIVE'
        else:
            state = 'UNKNOWN'

        print("\nTopology is Changed (Port is Changed at datapath ID of {}) - Reason={} - Port No={}, State={} -- Log at: {}"
            .format(dp.id,reason_st,port_no, state, datetime.datetime.now()))
        
        #Find the removed MAC address
        if reason_st == 'DELETE' or state == 'DOWN' or state == 'BLOCKED':
            if dp.id in self.MAC_table.keys():
                _have_mac = False
                for _mac in self.MAC_table[dp.id].keys():
                    if self.MAC_table[dp.id][_mac] == port_no:
                        _have_mac = True
                        break
                
                if (_have_mac):
                    #Remove invalid entries from the flow table of OFSs
                    print("   - Remove invalid entries from the flow table")
                    for _dp in self.datapaths.values():
                        _match   = _dp.ofproto_parser.OFPMatch(eth_dst=_mac)
                        self.flow_remove(_dp, _match)
                    
                    #Remove invalided entries from tables (MAC, ARP)
                    print("   - Remove invalid entries of {} from the MAC/ARP table".format(_mac))
                    self.MAC_table[dp.id].pop(_mac)
                    self.ARP_table[dp.id].pop(_mac)

        #Network is changed => Call update topology
        if reason_st == 'ADD':
            if(self.network_changed_thread != None):
                hub.kill(self.network_changed_thread)
            self.network_changed_thread = hub.spawn_after(1,self.network_changed)

        if reason_st == 'DELETE':
            if dp.id in self.Topology_db.keys():
                for _dpid_dst in self.Topology_db[dp.id].keys():
                    if port_no == self.Topology_db[dp.id][_dpid_dst][0]:
                        #This port connect to another OFS => Network changed
                        if(self.network_changed_thread != None):
                            hub.kill(self.network_changed_thread)
                        self.network_changed_thread = hub.spawn_after(1,self.network_changed)
                        break

    def flow_add(self, dp,idle_timeout, priority, match, instructions):
    
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        mod        = ofp_parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_ADD, 
                                           priority=priority, match=match, instructions=instructions)
        dp.send_msg(mod)
    
    # Add Flow
    
    def flow_remove(self,dp,match):
        ofp         = dp.ofproto
        ofp_parser  = dp.ofproto_parser
        mod         = ofp_parser.OFPFlowMod(datapath=dp,command = ofp.OFPFC_DELETE, out_port = ofp.OFPP_ANY,out_group=ofp.OFPP_ANY,match=match)
        print ("        + Flow (REMOVE) of Datapath ID = {}, Match: (Destination MAC = {})".format(dp.id,match["eth_dst"]))
        dp.send_msg(mod)
    
    # Network Changed:
    # Switch is added

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        print("\nSwitch entering (Datapath ID = {}) --------------- Log at: {}".format(ev.switch.dp.id, datetime.datetime.now()))
        if(self.network_changed_thread != None):
            hub.kill(self.network_changed_thread)
        self.network_changed_thread = hub.spawn_after(1,self.network_changed)
    
    # Switch is removed/unavailable

    @set_ev_cls(event.EventSwitchLeave)
    def handler_switch_leave(self, ev):
        print("\nSwitch leaving (Datapath ID = {}) --------------- Log at: {}".format(ev.switch.dp.id, datetime.datetime.now()))
        if(self.network_changed_thread != None):
            hub.kill(self.network_changed_thread)
        self.network_changed_thread = hub.spawn_after(1,self.network_changed)

    # Update the topology
    #   * No care end hosts
    
    def network_changed(self):
        print("\nNetwork is changed------------------------------- Log at: {}".format(datetime.datetime.now()))
        self.topo_raw_links = get_link(self, None)
        self.topo_raw_switches = get_switch(self,None)
        for _dpid in self.MAC_table.keys():
            for _mac in self.MAC_table[_dpid].keys():
                for _dp in self.datapaths.values():
                    _match   = _dp.ofproto_parser.OFPMatch(eth_dst=_mac)
                    self.flow_remove(_dp, _match)

        self.BuildTopology()

    def BuildTopology(self):
        self.Topology_db.clear()

        for l in self.topo_raw_links:
            _dpid_src = l.src.dpid
            _dpid_dst = l.dst.dpid
            _port_src = l.src.port_no
            _port_dst = l.dst.port_no
            
            self.Topology_db.setdefault(_dpid_src,{})
            self.Topology_db[_dpid_src][_dpid_dst] = [_port_src,_port_dst]
        
            self.Switch_switch_db.setdefault(_dpid_src,{})
            
            self.Switch_switch_db[_dpid_src][_dpid_dst]=[_port_src,_port_dst]

            
            

        print("")
        print("   - Topology Database: {}".format(self.Topology_db))
        print("")
        print("   - Switch-Switch Link Database: {}".format(self.Switch_switch_db))



        for l in self.topo_raw_switches:
            dpid_src=l.dp.id
            self.switch_port_connect=[]
            for m in range(len(l.ports)):
                
                self.port_connect = l.ports[m].port_no
                m=m+1
                self.switch_port_connect.append(self.port_connect)
                
            self.port_switch[dpid_src]=self.switch_port_connect   
        print("")
        print("   - All switch-port Database: {}".format(self.port_switch))
        print("")

        count=0
        count_1=0
        for l in self.port_switch.keys():            
            for z in self.port_switch.values()[l-1]:
                for m in self.Topology_db[l].values():
                    p=self.Topology_db[l].values()[count][0]
                    count=count+1
                
                    if p !=z:
                        count_1=count_1+1
                        if count_1 == len(self.Topology_db[l].values()):
                            self.host_connect=z
                            self.port_host_connect.append(self.host_connect)
                            self.port_host[self.port_switch.keys()[l-1]]=self.port_host_connect     
                    else:
                        self.port_host_connect=[]    
                        count=0
                        break
                count=0             
                count_1=0
                    
        print("")
        print("   - Host-port Database: {}".format(self.port_host))

        self.filter_link_connection_between_switch()
        print("")
        self.filter_link_connection_between_switch_for_drop()

  
    # Filter the connection between switch to find the link loss

    def filter_link_connection_between_switch(self):
        for l in range(len(self.Topology_db.keys())): 
            self.link_connection_switch.setdefault(self.Topology_db.keys()[l],{}) 
            for i in range(l+1,len(self.Topology_db.keys())): 
                for dp_id in self.Topology_db.values()[i].keys():
                    for dpid in self.Topology_db.values()[l].keys():
                        if dp_id ==  self.Topology_db.keys()[l]:
                            if dpid == self.Topology_db.keys()[i]: 
                                self.link_connection_switch[dp_id][dpid]=0 
        #--------------------------------------------------------------------------

        for key,values in list(self.link_connection_switch.items()):
            if len(values) == 0:
                del self.link_connection_switch[key]
        #--------------------------------------------------------------------------
        
        for dp in self.Topology_db.keys():
            if dp in self.link_connection_switch.keys():
                for key in self.link_connection_switch[dp].keys():
                    if key in self.Topology_db.keys():
                            self.link_connection_switch[dp][key] = self.Topology_db[dp][key]  
        print("   - All switch-switch link filter: {}".format(self.link_connection_switch))               

        
    # Filter the connection between switch to apply the drop rule
    
    def filter_link_connection_between_switch_for_drop(self):
        for dpid in self.Topology_db.keys():
            if dpid not in self.link_connection_switch.keys():
                self.switch_drop.setdefault(dpid,{})
                self.switch_drop[dpid]=self.Topology_db[dpid]
        print("   - All destination switch: {}".format(self.switch_drop))
    
    # Find the best route using DFS (Depth First Search) algorithm

    def send_packet(self, datapaths,buffer_id, in_port,actions, data):
        ofproto=datapaths.ofproto
        ofp_parser=datapaths.ofproto_parser

        if buffer_id != 0 :
            out=ofp_parser.OFPPacketOut(datapath=datapaths,buffer_id= buffer_id,
                                                                in_port=in_port,actions=actions,data=data)
        else:
            out=ofp_parser.OFPPacketOut(datapath=datapaths,buffer_id=ofproto.OFP_NO_BUFFER,
                                                                in_port=in_port,actions=actions,data=data)
        datapaths.send_msg(out)
   
  
    # Count the number of switches
    
    def switches_count(self):
        return len(self.topo_raw_switches)

    def FindRoute(self,dpid_src,dpid_dst):
        # Case 1: Destination is on the same Switch:
        if dpid_src == dpid_dst:
            return [dpid_src]
        
        # Case 2: Destination is on another Switch:
        paths = []
        stack = [(dpid_src, [dpid_src])]
        while stack:
            (node, path) = stack.pop()
            for next_node in set(self.Topology_db[node].keys()) - set(path):
                if next_node == dpid_dst:
                    paths.append(path + [next_node])
                else:
                    stack.append((next_node, path + [next_node]))

        # The best route is the route having the 'minimum hop count'
        shortest_path_hops = 1000
        for path in paths:
            if len(path) < shortest_path_hops:
                shortest_path_hops = len(path)
                shortest_path = path
        
        print("   - Routing request from {} to {} ---> Result: {}  (Datapath ID)".format(dpid_src, dpid_dst, shortest_path))
        return shortest_path

    #Find the exit interface
    def Get_port_out (self,dpid_src,dpid_dst,mac):
        # Destination is on the same Switch:
        if dpid_src == dpid_dst:
            return self.MAC_table[dpid_src][mac]

        return self.Topology_db[dpid_src][dpid_dst][0]

    
    #Send the number of switch in topology
    
    def num_switches(self):
        return len(self.topo_raw_switches)
