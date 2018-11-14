//
//  Util.cpp
//  sniffer
//
//  Created by ziteng on 18-11-12
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include "Util.h"


CLock::CLock()
{
    pthread_mutex_init(&m_lock, NULL);
}

CLock::~CLock()
{
    pthread_mutex_destroy(&m_lock);
}

void CLock::lock()
{
    pthread_mutex_lock(&m_lock);
}

void CLock::unlock()
{
    pthread_mutex_unlock(&m_lock);
}


int daemonize()
{
    pid_t pid = fork();
    if (pid == -1) {
        fprintf(stderr, "fork failed\n");
        return -1;
    } else if (pid > 0) {
        exit(0);
    }
    
    umask(0);
    setsid();
    
    // close all open file
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    if (rl.rlim_max > 1024) {
        rl.rlim_max = 1024;
    }
    
    for (int i = 0; i < rl.rlim_max; i++) {
        close(i);
    }
    
    // attach file descriptor 0, 1, 2 to "dev/null"
    int fd = open("/dev/null", O_RDWR, 0666);
    if (fd == -1) {
        fprintf(stderr, "open failed\n");
        return -1;
    }
    
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    
    return 0;
}

