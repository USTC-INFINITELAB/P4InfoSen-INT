/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<8>  egressSpec_t;
typedef bit<8>  ingressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;
typedef bit<32> byte_cnt_t;
typedef bit<32> sampling_ratio_t;
typedef bit<48> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header int_header_t {
    bit<8>      hop_count;
}

header bridge_t {
    bit<8>             if_egress;
    bit<8>             if_polling;
    bit<8>             time;
    ingressSpec_t      port;
    egressSpec_t       eport;
    bit<8>             first_pkt;
    int<8>             highest_priority;
    int<8>             priority_bd;
    bit<8>             index;
    switchID_t         swid;
    time_t             ingress_tstamp;
}

header sw_t {
    switchID_t         swid;
}

header mapinfo_t {
    bit<8>            MapInfo;
}

header metadata_t {
    bit<16>            md;
}

header polling_md_t{
    bit<16>           hop_t;
    bit<16>           bd; 
    bit<8>           outport;
    bit<8>           inport;
}

struct ingress_metadata_t {
    bit<8>             polling_threshold;
    bit<8>             polling_num;
    bit<8>             demand_collect;
    bit<8>             judge;
    bit<16>           hash_value;
    bit<16>           threshold;
    bit<16>             packet_num;
}

struct egress_metadata_t {
    int<8>             priority_inport;
    int<8>             priority_outport;
    int<8>             priority_hop_t;
    bit<8>             port;
    bit<8>             eport;
    int<8>             max_num;
    bit<8>             mapinfo;
    bit<8>             temp;
    int<8>             diff;
    int<8>             diff_1;
    bit<8>             final_map;
    int<8>             max_number;
    int<8>             max_number_1;
    bit<8>             mapinfo_1;
    bit<8>             mapinfo_2;
    bit<8>             md_1;
    bit<16>            hop_t;
    bit<16>            bytes;
    bit<16>            metadata;
    bit<16>            final_md;
    bit<16>            md;
}


struct header_t {
    bridge_t           bridge;
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    tcp_t              tcp;
    int_header_t       int_header;
    sw_t               sw;
    mapinfo_t          mapinfo;
    metadata_t      metadata;
    polling_md_t    polling_md;
}