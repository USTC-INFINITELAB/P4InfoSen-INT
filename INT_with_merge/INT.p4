/* -*- P4_16 -*- */
// implement INT without using array int_md[MAX_HOPS]

#include <core.p4>
#include <tna.p4>
#include "include/util.p4"
#include "include/header.p4"

const bit<16> TYPE_IPV4 = 16w0x800;
const bit<8>  INT_PROTOCOL = 8w0xff;
const bit<8>  TYPE_TCP = 8w0x6;

#define MAX_FLOWS 256
struct bytes_count {
    bit<16> count_1;
    bit<16> count_2;
}

/*************************************************************************
*********************** I N G R E S S   P A R S E R  *********************
*************************************************************************/

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md){

        TofinoIngressParser() tofino_parser;

        state start {
            tofino_parser.apply(pkt, ig_intr_md);
            ig_md.threshold = 0;
            ig_md.polling_threshold = 0;
            ig_md.packet_num = 0;
            ig_md.polling_num = 0;
            ig_md.demand_collect = 0;
            ig_md.judge = 0;
            ig_md.hash_value = 0;
            transition parse_ethernet;
        }

        state parse_ethernet {
            pkt.extract(hdr.ethernet);
            transition select(hdr.ethernet.etherType){
                TYPE_IPV4: parse_ipv4;
                default: accept;
            }
        }

        state parse_ipv4 {
            pkt.extract(hdr.ipv4);
            transition select(hdr.ipv4.protocol){
                TYPE_TCP: parse_tcp;
                INT_PROTOCOL: parse_tcp;
                default:  accept;
            }
        }

        state parse_tcp{
            pkt.extract(hdr.tcp);
            transition select(hdr.ipv4.protocol){
                INT_PROTOCOL: parse_int_header;
                default: accept;
            }
        }

        state parse_int_header{
            pkt.extract(hdr.int_header);
            transition accept;
        }
}

/*************************************************************************
**************  I N G R E S S   CONTROL   ********************************
*************************************************************************/

control SwitchIngress(inout header_t hdr,
                      inout ingress_metadata_t ig_md,
                      in ingress_intrinsic_metadata_t ig_intr_md,
                      in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                      inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    Hash<bit<16>>(HashAlgorithm_t.CRC16) my_hash;

    /*Register<T1, T2>, T1 is the type of value stored in the register,
        T2 is the index type*/
    Register<bit<16>, bit<8>>(MAX_FLOWS, 0) packet_num;
    Register<bit<8>, bit<8>>(MAX_FLOWS, 0) polling_count;
    Register<bit<32>, bit<8>>(MAX_FLOWS, 0) timer;
//    Register<bit<8>, bit<1>>(1, 0) test;

    /*RegisterAction<T1, T2, T3>, T1 is the type of value stored in the register,
    T2 is the index type,
    T3 is the type of return value*/

    RegisterAction<bit<32>, bit<8>, bit<8>>(timer) time_update = {
        void apply(inout bit<32> value, out bit<8> read_value){
            if (ig_intr_prsr_md.global_tstamp[31:0] - value >= 50000 || value >= ig_intr_prsr_md.global_tstamp[31:0]){
                read_value = 1;
                value = ig_intr_prsr_md.global_tstamp[31:0];
            } else{
                read_value = 0;
            }
        }
    };

    RegisterAction<bit<16>, bit<8>, bit<16>>(packet_num) reg_update = {
        void apply(inout bit<16> value, out bit<16> read_value){
            if (value >= ig_md.threshold){
                value = 1;
            } else{
                value = value + 1;
            }
            read_value = value;
        }
    };

    RegisterAction<bit<8>, bit<8>, bit<8>>(polling_count) polling_update = {
        void apply(inout bit<8> value, out bit<8> read_value){
            if (value == ig_md.polling_threshold){
                value = 1;
            } else{
                value = value + 1;
            }
            read_value = value;
        }
    };

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }

    action ipv4_forward(egressSpec_t port) {
        ig_intr_tm_md.ucast_egress_port = (bit<9>) port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action int_source(switchID_t swid, bit<16> threshold, bit<8> polling_threshold, bit<8> index, bit<8> demand_collect) {
        hdr.int_header.setValid();
        hdr.int_header.hop_count = 8w0x1;
        hdr.ipv4.protocol = INT_PROTOCOL;
        hdr.bridge.swid = swid;
        hdr.bridge.port = ig_intr_md.ingress_port[7:0];
        hdr.bridge.eport = ig_intr_tm_md.ucast_egress_port[7:0];
        hdr.bridge.ingress_tstamp = ig_intr_prsr_md.global_tstamp;
        hdr.bridge.index = index;
        ig_md.threshold = threshold;
        ig_md.polling_threshold = polling_threshold;
        ig_md.demand_collect = demand_collect;
        ig_md.judge = 8w0x1;
    }

    action int_transmit(switchID_t swid, bit<16> threshold, bit<8> polling_threshold, bit<8> index, bit<8> demand_collect){
        hdr.int_header.hop_count = hdr.int_header.hop_count + 1;
        hdr.bridge.swid = swid;
        hdr.bridge.port = ig_intr_md.ingress_port[7:0];
        hdr.bridge.eport = ig_intr_tm_md.ucast_egress_port[7:0];
        hdr.bridge.ingress_tstamp = ig_intr_prsr_md.global_tstamp;
        hdr.bridge.index = index;
        ig_md.threshold = threshold;
        ig_md.polling_threshold = polling_threshold;
        ig_md.demand_collect = demand_collect;
        ig_md.judge = 8w0x1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = NoAction;
    }

    table int_match {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            int_source;
            int_transmit;
            NoAction;
        }
        size = 256;
        const default_action = NoAction;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            hdr.bridge.setValid();
            if (hdr.tcp.isValid()) {
                ig_md.hash_value = my_hash.get({hdr.ipv4.srcAddr,
                                                                    hdr.ipv4.dstAddr,
                                                                    hdr.ipv4.protocol,
                                                                    hdr.tcp.src_port,
                                                                    hdr.tcp.dst_port});
                int_match.apply();
            }
         }
         if (ig_md.judge == 8w0x1){
             ig_md.packet_num = reg_update.execute(hdr.bridge.index);
             hdr.bridge.time = time_update.execute(hdr.bridge.index);
             if (ig_md.packet_num == 16w0x1) {
                 hdr.bridge.first_pkt = 8w0x1;
             }
             if (ig_md.packet_num == ig_md.threshold){
                 hdr.bridge.if_egress = 8w0x1;
                 ig_md.polling_num = polling_update.execute(hdr.bridge.index);
             }
             if (ig_md.polling_num == ig_md.polling_threshold && ig_md.demand_collect == 8w0x0){
                    hdr.bridge.if_polling = 8w0x1;
             }
         } 
    }
}

/*************************************************************************
****************  I N G R E S S   D E P A R S E R   **********************
*************************************************************************/

control SwitchIngressDeparser(packet_out pkt,
                              inout header_t hdr,
                              in ingress_metadata_t ig_md,
                              in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {
        // Updating and checking of the checksum is done in the deparser.
        // Checksumming units are only available in the parser sections of
        // the program.

            hdr.ipv4.hdrChecksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.totalLen,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.fragOffset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.srcAddr,
                 hdr.ipv4.dstAddr});

            pkt.emit(hdr.bridge);
            pkt.emit(hdr.ethernet);
            pkt.emit(hdr.ipv4);
            pkt.emit(hdr.tcp);
            pkt.emit(hdr.int_header);
    }
}


/*************************************************************************
*********************** E G R E S S   P A R S E R  ***********************
*************************************************************************/

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md){

        TofinoEgressParser() tofino_parser;

        state start {
            tofino_parser.apply(pkt, eg_intr_md);
            eg_md.hop_t = 0;
            eg_md.max_num = 0;
            eg_md.mapinfo = 0;
            eg_md.metadata = 0;
            eg_md.temp = 0;
            eg_md.final_map = 0;
            eg_md.final_md = 0;
            eg_md.bytes = 0;
            transition parse_bridge;
        }

        state parse_bridge{
            pkt.extract(hdr.bridge);
            eg_md.port = hdr.bridge.port;
            eg_md.eport = hdr.bridge.eport;
            transition parse_ethernet;
        }

        state parse_ethernet {
            pkt.extract(hdr.ethernet);
            transition select(hdr.ethernet.etherType){
                TYPE_IPV4: parse_ipv4;
                default: accept;
            }
        }

        state parse_ipv4 {
            pkt.extract(hdr.ipv4);
            transition select(hdr.ipv4.protocol){
                TYPE_TCP: parse_tcp;
                INT_PROTOCOL: parse_tcp;
                default:  accept;
            }
        }

        state parse_tcp{
            pkt.extract(hdr.tcp);
            transition select(hdr.ipv4.protocol){
                INT_PROTOCOL: parse_int_header;
                default: accept;
            }
        }

        state parse_int_header{
            pkt.extract(hdr.int_header);
            transition accept;
        }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

   // Random<bit<16>>() rand;
    /*Register<T1, T2>, T1 is the type of value stored in the register,
        T2 is the index type*/
    Register<int<8>, bit<8>>(MAX_FLOWS, 0) dbt_priority;
    Register<bit<8>, bit<8>>(MAX_FLOWS, 0) dbt_mapinfo;
    Register<bit<16>, bit<8>>(MAX_FLOWS, 0) dbt_metadata;
    Register<bytes_count, bit<8>>(MAX_FLOWS, {0, 0}) packet_bytes;


    /*RegisterAction<T1, T2, T3>, T1 is the type of value stored in the register,
    T2 is the index type,
    T3 is the type of return value*/

    RegisterAction<bytes_count, bit<8>, bit<16>>(packet_bytes) bytes_update = {
        void apply(inout bytes_count value, out bit<16> read_value){
            if (hdr.bridge.time==1){
                value.count_1 = value.count_2;
                value.count_2 = (bit<16>) eg_intr_md.pkt_length;
           } else{
                value.count_2 = value.count_2 + (bit<16>) eg_intr_md.pkt_length;
            }
            read_value = value.count_1;
        }
    };

    RegisterAction<int<8>, bit<8>, bit<8>>(dbt_priority) dbt_priority_init = {
        void apply(inout int<8> value, out bit<8> read_value){
            value = eg_md.max_num;
            read_value = 0;
        }
    };

    RegisterAction<int<8>, bit<8>, bit<8>>(dbt_priority) dbt_priority_action = {
        void apply(inout int<8> value, out bit<8> read_value){
            if (eg_md.max_num - value >= 0){
                value = eg_md.max_num;
                read_value = 0;
            } else{
                read_value = 1;
            }
        }
    };

    RegisterAction<bit<8>, bit<8>, bit<8>>(dbt_mapinfo) dbt_mapinfo_action = {
        void apply(inout bit<8> value, out bit<8> read_value){
            if (eg_md.temp == 0) {
                value = eg_md.mapinfo;
            }
            read_value = value;
        }
    };

    RegisterAction<bit<16>, bit<8>, bit<16>>(dbt_metadata) dbt_metadata_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            if (eg_md.temp == 0) {
                value = eg_md.metadata;
            }
            read_value = value;
        }
    };

    action add_polling_md () {
        hdr.sw.setValid();
        hdr.sw.swid = hdr.bridge.swid;
        hdr.mapinfo.setValid();
        hdr.mapinfo.MapInfo = 8w0x5;
        hdr.polling_md.setValid();
        hdr.polling_md.outport = eg_md.eport;
        hdr.polling_md.inport = eg_md.port;
        hdr.polling_md.hop_t = eg_md.hop_t;
        hdr.polling_md.bd = eg_md.bytes;
    }

    action add_md () {
        hdr.sw.setValid();
        hdr.sw.swid = hdr.bridge.swid;
        hdr.mapinfo.setValid();
        hdr.mapinfo.MapInfo = eg_md.final_map;
        hdr.metadata.setValid();
        hdr.metadata.md = eg_md.final_md;
    }

    action select_port(int<8> priority, bit<8> mapinfo){
        eg_md.max_num = priority;
        eg_md.mapinfo = mapinfo;
        eg_md.metadata = (bit<16>) hdr.bridge.port;
    }

    action select_eport(int<8> priority, bit<8> mapinfo){
        eg_md.max_num = priority;
        eg_md.mapinfo = mapinfo;
        eg_md.metadata = (bit<16>) hdr.bridge.eport;
    }

    action select_hop_t(int<8> priority, bit<8> mapinfo){
        eg_md.max_num = priority;
        eg_md.mapinfo = mapinfo;
        eg_md.metadata = eg_md.hop_t;
    }

    action select_bytes(int<8> priority, bit<8> mapinfo){
        eg_md.max_num = priority;
        eg_md.mapinfo = mapinfo;
        eg_md.metadata = eg_md.bytes;
    }

    table imt {
        key = {
            hdr.bridge.index: exact;
            hdr.bridge.port: ternary;
            hdr.bridge.eport: ternary;
            eg_md.hop_t: range;
            eg_md.bytes: range;
        }
        actions = {
            select_port;
            select_eport;
            select_hop_t;
            select_bytes;
        }
        size = 1505;
    }

    apply {
        if (hdr.int_header.isValid()){
            eg_md.hop_t = (eg_intr_from_prsr.global_tstamp - hdr.bridge.ingress_tstamp) [15:0]; //stage 0
            eg_md.bytes = bytes_update.execute(hdr.bridge.index);  //stage 0
            imt.apply();    //stage 2

            if (hdr.bridge.first_pkt == 1){  //stage 3
                eg_md.temp = dbt_priority_init.execute(hdr.bridge.index);  //stage 3
            }else{
                eg_md.temp = dbt_priority_action.execute(hdr.bridge.index);    //stage 3
            }

            eg_md.final_map = dbt_mapinfo_action.execute(hdr.bridge.index);    //stage 4
            eg_md.final_md = dbt_metadata_action.execute(hdr.bridge.index);    //stage 4

            if (hdr.bridge.if_egress == 8w0x1){    //stage 5
                if (hdr.bridge.if_polling == 1){
	                add_polling_md();
	            } else{
	                add_md();
	            }
            } else{
                hdr.int_header.setInvalid();    //stage 5
                hdr.ipv4.protocol = TYPE_TCP;    //stage 5
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   D E P A R S E R   ************************
*************************************************************************/

control SwitchEgressDeparser(
         packet_out pkt,
         inout header_t hdr,
         in egress_metadata_t eg_md,
         in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md){
    Checksum() ipv4_checksum;
    apply {
            // Updating and checking of the checksum is done in the deparser.
            // Checksumming units are only available in the parser sections of
            // the program.

            hdr.ipv4.hdrChecksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.totalLen,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.fragOffset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.srcAddr,
                 hdr.ipv4.dstAddr});

            pkt.emit(hdr.ethernet);
            pkt.emit(hdr.ipv4);
            pkt.emit(hdr.tcp);
            pkt.emit(hdr.int_header);
            pkt.emit(hdr.mapinfo);
            pkt.emit(hdr.sw);
            pkt.emit(hdr.metadata);
            pkt.emit(hdr.polling_md);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
