/*************************************
* Lab 4
* Name: Darien Chong
* Student No: A0168214H
* Lab Group: 6
*************************************/

#include "mmf.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdio.h>

bool is_debug = false;

/**
 * Opens a file if it exists, or creates it if it doesn't.
 * Returns the file descriptor.
 */
int mmf_create_or_open_file(const char *name) {
	if (is_debug) {
		printf("\n[mmf_create_or_open_file(%d)]: Function called with parameters: name=[%s].\n", getpid(), name);
	}
	return open(name, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
}

void *mmf_map_file_by_fd(int fd, size_t sz) {
	if (is_debug) {
		printf("\n[mmf_map_file_by_fd(%d)]: Function called with parameters: fd=[%d], sz=[%ld].\n", getpid(), fd, sz);
	}
	void *to_return = mmap(NULL, sz, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
	
	// If the file length is less than sz, we need to ftruncate it to extend it (pad it with zeroes)
	// This ensures that we don't get a bus error when attempting to write beyond
	// the current file size (if the file was newly created, that's 0).
	ftruncate(fd, sz);
	
	return to_return;
}

void *mmf_map_file_by_name(const char *name, size_t sz) {
	if (is_debug) {
		printf("\n[mmf_map_file_by_name(%d)]: Function called with parameters: name=[%s], sz=[%ld].\n", getpid(), name, sz);
	}
	int fd = mmf_create_or_open_file(name);
  	
  	if (is_debug) {
  		printf("[mmf_map_file_by_name(%d)]: mmf_create_or_open_file return value: [%d].\n", getpid(), fd);
  	}
  	
  	void *to_return = mmf_map_file_by_fd(fd, sz);
  	
  	if (is_debug) {
  		printf("[mmf_map_file_by_name(%d)]: mmf_map_file_by_fd return value: [%p].\n", getpid(), to_return);
  	}
  	close(fd);
  	return to_return;
}

void *mmf_create_or_open(const char *name, size_t sz) {
	if (is_debug) {
		printf("\n[mmf_create_or_open(%d)]: Function called with parameters: name=[%s], sz=[%ld].\n", getpid(), name, sz);
	}
	return mmf_map_file_by_name(name, sz);
}

void mmf_close(void *ptr, size_t sz) {
	if (is_debug) {
		printf("\n[mmf_close(%d)]: Function called with parameters: ptr=[%p], sz=[%ld].\n", getpid(), ptr, sz);
	}
    int result = munmap(ptr, sz);
    
    if (is_debug) {
    	printf("[mmf_close(%d)]: munmap return value: [%d].\n", getpid(), result);
    }
    
    if (result != 0) {
    	// munmap() failed
    	// Do something?
    }
}
