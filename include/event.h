#ifndef EVENT_H
#define EVENT_H

struct openat_event {
    unsigned int pid;
    unsigned int tgid;

    int dirfd;
    unsigned int flags;
    unsigned int mode;

    char comm[16];
    char filename[256];
};

#endif
