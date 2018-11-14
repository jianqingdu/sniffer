//
//  SnifferThread.h
//  sniffer
//
//  Created by ziteng on 18-11-12
//

#ifndef __SNIFFER_THREAD_H__
#define __SNIFFER_THREAD_H__

#include <pcap/pcap.h>
#include <string>

using namespace std;

class CSnifferThread
{
public:
    CSnifferThread();
    virtual ~CSnifferThread();
    
    int StartSniffer(const char* device_name, const char* filter_rule);
    void StartCaptureLoop();
    
    static void* StartThread(void* arg);
private:
    string      m_device_name;
    pcap_t*     m_pcap_handle;
    long        m_device_type;
};

#endif
