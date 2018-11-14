//
//  PacketHandler.h
//  sniffer
//
//  Created by ziteng on 18-11-12
//

#ifndef __PACKET_HANDLER_H__
#define __PACKET_HANDLER_H__

#include <stdint.h>
#include <pcap/pcap.h>

class CPacketHandler {
public:
    CPacketHandler() {}
    virtual ~CPacketHandler() {}
    
    static int Init(char* save_file, uint32_t max_file_size, char* content);
    static void ReceivePacket(u_char* arg, const struct pcap_pkthdr* ph, const u_char* packet);
};

#endif
