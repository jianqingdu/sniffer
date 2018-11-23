//
//  SnifferThread.cpp
//  sniffer
//
//  Created by ziteng on 18-11-12
//

#include <pthread.h>
#include "SnifferThread.h"
#include "PacketHandler.h"

#define SNAP_LEN     1024

void* CSnifferThread::StartThread(void* arg)
{
    CSnifferThread* obj = (CSnifferThread*)arg;
    obj->StartCaptureLoop();
    
    return NULL;
}

CSnifferThread::CSnifferThread()
{
    
}

CSnifferThread::~CSnifferThread()
{
    if (m_pcap_handle) {
        pcap_close(m_pcap_handle);
    }
}

int CSnifferThread::StartSniffer(const char* device_name, const char* filter_rule)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    
    m_device_name = device_name;
    
    if (pcap_lookupnet(device_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "can't get netmask for device %s: %s\n", device_name, errbuf);
        return 1;
    }
    
    m_pcap_handle = pcap_open_live(device_name, SNAP_LEN, 1, 1000, errbuf);
    if (!m_pcap_handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }
    
    m_device_type = pcap_datalink(m_pcap_handle);
    if ((m_device_type != DLT_NULL) && (m_device_type != DLT_EN10MB)) {
        fprintf(stderr, "not a loopback or ethernet device\n");
        return 1;
    }
    
    if (filter_rule) {
        struct bpf_program filter;
        if (pcap_compile(m_pcap_handle, &filter, filter_rule, 1, mask) == -1) {
            fprintf(stderr, "pcap_compile failed\n");
            return 1;
        }
        
        if (pcap_setfilter(m_pcap_handle, &filter) == -1) {
            printf("pcap_setfilter failed\n");
            return 1;
        }
    }
    
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, StartThread, this);
    
    return 0;
}

void CSnifferThread::StartCaptureLoop()
{
    fprintf(stderr, "start capture for device: %s\n", m_device_name.c_str());
    int ret = pcap_loop(m_pcap_handle, -1, CPacketHandler::ReceivePacket, (u_char*)m_device_type);
    if (ret == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(m_pcap_handle));
    }
    
    printf("after pcap_loop\n");
}
