/*************************************
* Lab 4
* Name: Darien Chong
* Student No: A0168214H
* Lab Group: 6
*************************************/

#include "shmheap.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

bool is_debug = true;

int _shmheap_get_prot_permissions() {
	return PROT_EXEC | PROT_READ | PROT_WRITE;
}

shmheap_memory_handle shmheap_create(const char *name, size_t len) {
	shmheap_memory_handle mem_handle;
	
	int shm_fd = shm_open(name, O_CREAT | O_RDWR | O_EXCL, 0777);
	
	if (is_debug && shm_fd == -1) {
		printf("[shmheap_create]: Failed to create shared memory.\n");
	}
	
	ftruncate(shm_fd, len);
	void *mmap_ptr = mmap(NULL, len, _shmheap_get_prot_permissions(), MAP_SHARED, shm_fd, 0);
	
	mem_handle.name = malloc(sizeof(char) * (strlen(name) + 1));
	strcpy(mem_handle.name, name);
	mem_handle.shm_fd = shm_fd;
	mem_handle.mmap_ptr = mmap_ptr;
	mem_handle.shm_len = len;
	
	return mem_handle;
}

shmheap_memory_handle shmheap_connect(const char *name) {
	shmheap_memory_handle mem_handle;
	
	int shm_fd = shm_open(name, O_RDWR, -1);
	
	if (is_debug && shm_fd == -1) {
		printf("[shmheap_connect]: Failed to open shared memory.\n");
	}
	
	struct stat buf;
	fstat(shm_fd, &buf);
	size_t shm_size = buf.st_size;
	void *mmap_ptr = mmap(NULL, shm_size, _shmheap_get_prot_permissions(), MAP_SHARED, shm_fd, 0);
	
	mem_handle.name = malloc(sizeof(char) * (strlen(name) + 1));
	strcpy(mem_handle.name, name);
	mem_handle.shm_fd = shm_fd;
	mem_handle.mmap_ptr = mmap_ptr;
	mem_handle.shm_len = shm_size;
	
	return mem_handle;
}

void shmheap_disconnect(shmheap_memory_handle mem) {
    int munmap_result = munmap(mem.mmap_ptr, mem.shm_len);
    if (is_debug && munmap_result == -1) {
    	printf("[shmheap_disconnect]: Failed to unmap shared memory.\n");
    }
    
    return;
}

void shmheap_destroy(const char *name, shmheap_memory_handle mem) {
    int munmap_result = munmap(mem.mmap_ptr, mem.shm_len);
    if (is_debug && munmap_result == -1) {
    	printf("[shmheap_destroy]: Failed to unmap shared memory.\n");
    }
    
    free(mem.name);
    shm_unlink(name);
    
    return;
}

void *shmheap_underlying(shmheap_memory_handle mem) {
    /* TODO */
}

void *shmheap_alloc(shmheap_memory_handle mem, size_t sz) {
	mem.alloc_size = sz;
	
    return mem.mmap_ptr;
}

void shmheap_free(shmheap_memory_handle mem, void *ptr) {
    /* TODO */
}

shmheap_object_handle shmheap_ptr_to_handle(shmheap_memory_handle mem, void *ptr) {
	void *base_ptr = mem.mmap_ptr;
	int offset = (int) (ptr - base_ptr);
	
	shmheap_object_handle obj_handle;
	obj_handle.offset = offset;
	
	return obj_handle;
}

void *shmheap_handle_to_ptr(shmheap_memory_handle mem, shmheap_object_handle hdl) {
    void *ptr = mem.mmap_ptr + hdl.offset;
    return ptr;
}
