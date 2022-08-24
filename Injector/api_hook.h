#pragma once

#define MAX_BUF_SIZE 4096

struct mem
{
    int size;
    char buf[MAX_BUF_SIZE + 14];
};

void* copy_func(void*);
void hook_func(void*, void*);
void restore_func(void*, void*);
