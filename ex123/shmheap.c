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

/**
 * Returns a pointer to the next shmheap_node in the linked-list, scoped to the process memory.
 * Returns NULL if no next pointer exists.
 */
void *_shmheap_get_next_ptr(shmheap_node *node_ptr) {
	if (node_ptr -> offset_to_next == 0) {
		if (is_debug) {
			printf("[_shmheap_get_next_ptr]: Reached end of linked list.\n");
		}
	
		return NULL;
	}
	
	return node_ptr + (node_ptr -> offset_to_next);
}

/**
 * Does a pass through the entire linked list and performs
 * up to one merge.
 * Returns true if a merge was performed, false otherwise.
 */
bool _shmheap_merge_helper(shmheap_node *head) {
	shmheap_node *curr_ptr = head;
	shmheap_node *next_ptr = (shmheap_node*) _shmheap_get_next_ptr(head);
	bool is_merged_partitions = false;
	
	while (next_ptr != NULL) {
		// Idea: 
		// Check if this partition is empty.
		// - If not empty, then move on.
		// - If empty, check if the next partition is empty.
		//   - If it is, we merge the two partitions (current + next)
		//     - current.offset_to_next = current_offset_to_next + next.offset_to_next
		//     - current.size = current.size + sizeof(shmheap_node) + next.size
		
		if (curr_ptr -> is_filled) {
			curr_ptr = next_ptr;
			next_ptr = (shmheap_node*) _shmheap_get_next_ptr(next_ptr);
			
			continue;
		}
		
		if (!(next_ptr -> is_filled)) {
			// Merge the two partitions
			curr_ptr -> offset_to_next = (curr_ptr -> offset_to_next) + (next_ptr -> offset_to_next);
			curr_ptr -> size = (curr_ptr -> size) + sizeof(shmheap_node) + (next_ptr -> size);
			
			return true;
		}
	}
	
	return false;
}

/**
 * Runs _shmheap_merge_helper in a loop until
 * no more merges detected. This is a separate method
 * to avoid using recursion (to avoid stack overflow for large heaps).
 */ 
void _shmheap_merge(shmheap_node *head) {
	bool merge_detected = true;
	
	while (merge_detected) {
		merge_detected = _shmheap_merge_helper(head);
	}
	
	return;
}

/**
 * Returns the first shmheap_node that is empty and has a size large enough
 * to hold an object of size_t size.
 */
shmheap_node *_shmheap_search_for_first_fit(shmheap_memory_handle mem, size_t size) {
	shmheap_node *head_ptr = (shmheap_node*) (mem -> mmap_ptr);
	shmheap_node *curr_ptr = head_ptr;
	
	while (curr_ptr != NULL) {
		if (!(curr_ptr -> is_filled) && ((curr_ptr -> size >= (size + sizeof(shmheap_node))))) {
			return curr_ptr;
		}
		
		curr_ptr = _shmheap_get_next_ptr(curr_ptr);
	}
	
	// We shouldn't get here, but...
	return NULL;
}

/**
 * Rounds up the size to the nearest multiple of 8.
 */
int _shmheap_round_up(size_t sz) {
	int i = sz / 8;
	int floor_mult_of_8 = 8 * i;
	if (sz == floor_mult_of_8) {
		return floor_mult_of_8;
	}
	return floor_mult_of_8 + 8;
}

shmheap_memory_handle shmheap_create(const char *name, size_t len) {
	shmheap_memory_handle mem_handle;
	
	int shm_fd = shm_open(name, O_CREAT | O_RDWR | O_EXCL, 0777);
	
	if (is_debug && shm_fd == -1) {
		printf("[shmheap_create]: Failed to create shared memory.\n");
	}
	
	ftruncate(shm_fd, len);
	void *mmap_ptr = mmap(NULL, len, _shmheap_get_prot_permissions(), MAP_SHARED, shm_fd, 0);
	
	// Set up the head node for the bookkeeping at the start of the shared memory.
	if (is_debug) {
		printf("[shmheap_create]: Bookkeeping node size = [%ld].\n", sizeof(shmheap_node));
	}
	
	shmheap_node head;
	head -> is_filled = false;
	head -> offset_to_next = 0;
	head -> size = len - sizeof(shmheap_node);
	memcpy(mmap_ptr, &head, sizeof(shmheap_node));
	
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
    return mem.mmap_ptr;
}

void *shmheap_alloc(shmheap_memory_handle mem, size_t sz) {
	/* TODO */
	int round_sz = _shmheap_round_up(sz);
	
	shmheap_node *node_ptr = _shmheap_search_for_first_fit(mem, sz);
	
	// Modify the current node (reduce size, set appropriate offset_to_next, flip is_filled)
	// Create a new node and copy it over to the appropriate spot.
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
