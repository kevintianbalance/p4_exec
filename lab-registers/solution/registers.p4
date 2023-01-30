/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define REGISTER_SIZE 1000
#define TIMESTAMP_WIDTH 48
#define HISTOGRAM_SIZE 32

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers {

    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

struct metadata {
    bit<1> enable_timestamp;
}

/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {

        transition parse_ethernet;

    }

    state parse_ethernet {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6 : parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    //TODO 1: Create 3 registers
    //Register that saves number of occurrences for inter-arrival time occurrencies
    // Number of bits per value is HISTOGRAM_SIZE, register size is REGISTER_SIZE
    register<bit<HISTOGRAM_SIZE>>(REGISTER_SIZE) interarrival_histogram; 
    //Register that, if equal to 1, enables inter-arrival time measurements
    // Number of bits per value is 1, register size is 1
    register<bit<1>>(1) enable_timestamp;
    //Register that stores the timestamp of previous tcp packet 
    // Number of bits per value is TIMESTAMP_WIDTH, register size is 1
    register<bit<TIMESTAMP_WIDTH>>(1) previous_timestamp_reg;

    //TODO 2: create table and action for packet forwarding based on ingress port.
    // You can copy-paste from Lab2 (Repeater)
    //Forwarding action on specified port
    action forward(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    // Standard table for packet forwarding
    table repeater {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward;
            NoAction;
        }
        size = 2;
        default_action = NoAction;
    }
    
    // TODO3: 
    // Create action and table to enable-disable inter-arrival time computations
    // The table should match the input port (we are only measuring interarrival time of
    // packets from h1 to h2), the tcp syn flag (if 1, we should start measuring) and the    
    // tcp fin flag (stops measuring)
    // The action should take as input a bit<1> value and set the register with the 
    // "enable_measurements" flag to the input value. It should also set the previous timestamp 
    // stored in the previous_timestamp register to 0

    // Enable or disable inter-arrival time measurements is enabled
    action set_enable_interarrival_time(bit<1> value_to_set){
        enable_timestamp.write((bit<32>)0, value_to_set);
        previous_timestamp_reg.write((bit<32>)0, standard_metadata.ingress_global_timestamp);
    }
    // Match syn, fin and ingress port flag: we consider only packets from host 1 to host 2 (and not viceversa)
    table synfin{
        actions = {
            set_enable_interarrival_time;
            NoAction;
        }
        key = {
            standard_metadata.ingress_port:   exact;
            hdr.tcp.syn:   exact;
            hdr.tcp.fin:   exact;
        }
        size = 1024;
        default_action = NoAction;
    }

    apply {
        // TODO 4:
        // Apply standard forwarding table
        // If the tcp header is valid:
        //      1) get the "enable_measurements" from the correspondent register
        //      2) apply the synfin table
        //      3) if the "enable_measurements" flag was true:
        //              3.1) get the current packet timestamp (standard_metadata.ingress_global_timestamp)
        //              3.2) Get the previous timestamp from the correspondent register and get the 
        //                   inter-arrival time by computing the time difference
        //              3.3) Get the bucket index by shifting to the right the interarrival time of some bits (e.g., 7). 
        //                   To shift a value, use "value>>num_bits_to_shift"
        //              3.4) If the index is higher than the register size - 1 , set it to register size - 1
        //              3.5) In the register that stores the buckets, increment by one the value stored at the index
        
        // Apply the repeater forwarding as always
        repeater.apply();
        //Perform inter-arrival time measurements only when tcp is used
        if(hdr.tcp.isValid()){
            // get the "enable_measurements" from the correspondent register
            enable_timestamp.read(meta.enable_timestamp, (bit<32>)0);
            // Apply the synfin table 
            synfin.apply();
            if(meta.enable_timestamp==1){
                // Compute time difference between last packet and current packet
                bit<TIMESTAMP_WIDTH> previous_timestamp;
                previous_timestamp_reg.read(previous_timestamp, (bit<32>)0);
                previous_timestamp_reg.write((bit<32>)0, standard_metadata.ingress_global_timestamp);
                bit<TIMESTAMP_WIDTH> delta_timestamp = standard_metadata.ingress_global_timestamp - previous_timestamp;
                //Compute bucket index given the time difference
                bit<TIMESTAMP_WIDTH> bucket_index = delta_timestamp >> 7;
                bit<HISTOGRAM_SIZE> previous_value;
                // If the index is greater than the register size REGISTER_SIZE, set it to last index of the register
                if(bucket_index>(bit<TIMESTAMP_WIDTH>)(REGISTER_SIZE-1)){
                    bucket_index = (bit<TIMESTAMP_WIDTH>)(REGISTER_SIZE-1);
                }
                //Read value from bucket and increment it by one. Then write it back to the same bucket
                interarrival_histogram.read(previous_value, (bit<32>)bucket_index);
                previous_value = previous_value + (bit<HISTOGRAM_SIZE>)1;
                interarrival_histogram.write((bit<32>)bucket_index, previous_value);
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;