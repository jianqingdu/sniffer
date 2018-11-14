//
//  Util.h
//  sniffer
//
//  Created by ziteng on 18-11-12
//

#ifndef __UTIL_H__
#define __UTIL_H__

#include <pthread.h>

class CLock
{
public:
    CLock();
    virtual ~CLock();
    void lock();
    void unlock();
private:
    pthread_mutex_t m_lock;
};

int daemonize();

#endif
