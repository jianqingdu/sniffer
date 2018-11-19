//
//  main.cpp
//  sniffer
//
//  Created by jianqing.du on 18-11-12
//

// see http://www.tcpdump.org/pcap.html for tutorial of programming with pcap
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <list>
#include <string>
#include "SnifferThread.h"
#include "PacketHandler.h"
#include "Util.h"

using namespace std;

void print_usage(const char* progname)
{
    printf("Usage: \n");
    printf("  %s -h\n", progname);
    printf("  %s [-d] [-i device_name] [-f save_file] [-m max_file_size(MB)] [-c content] -r filter_rule\n", progname);
}

int get_all_device(list<string>& device_list)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* all_devs;
    pcap_if_t* d;
    
    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        printf("pcap_findalldevs failed: %s\n", errbuf);
        return 1;
    }
    
    for (d = all_devs; d; d = d->next) {
        pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
        if (handle) {
            int device_type = pcap_datalink(handle);
            if ((device_type == DLT_NULL) || (device_type == DLT_EN10MB)) {
                //printf("name:%s, desc:%s, flags: 0x%x\n", d->name, d->description, d->flags);
                
                device_list.push_back(d->name);
            }
            
            pcap_close(handle);
        }
    }
    
    return 0;
}

int main(int argc, const char * argv[])
{
    const char* progname = argv[0];
    
    char* device_name = (char*)"any";
    char* save_file = NULL;
    char* filter_rule = NULL;
    char* content = NULL;
    int ch = 0;
    int max_file_size = 8*1024;  // MB
    bool daemon = false;
    
    while ((ch = getopt(argc, (char *const *)argv, "hdi:f:m:r:c:")) != -1) {
        switch (ch) {
            case 'h':
                print_usage(progname);
                return 0;
            case 'd':
                daemon = true;
            case 'i':
                device_name = optarg;
                break;
            case 'f':
                save_file = optarg;
                break;
            case 'r':
                filter_rule = optarg;
                break;
            case 'm':
                max_file_size = atoi(optarg);
                break;
            case 'c':
                content = optarg;
                break;
            case '?':
            default:
                print_usage(progname);
                return 1;
        }
    }
    
    printf("device=%s, save_file=%s, max_file_size=%d, content=%s, filter=%s\n",
           device_name, save_file, max_file_size, content, filter_rule);
    
    if (daemon) {
        daemonize();
    }
    
    if (CPacketHandler::Init(save_file, max_file_size, content)) {
        printf("init failed\n");
        return -1;
    }
    
    if (!device_name || !strcmp(device_name, "any")) {
        list<string> device_list;
        get_all_device(device_list);
        
        for (list<string>::iterator it = device_list.begin(); it != device_list.end(); ++it) {
            CSnifferThread* pThread = new CSnifferThread();
            pThread->StartSniffer(it->c_str(), filter_rule);
        }
    } else {
        CSnifferThread* pThread = new CSnifferThread();
        pThread->StartSniffer(device_name, filter_rule);
    }
    
    while (1) {
        sleep(1);
    }
    
    return 0;
}

