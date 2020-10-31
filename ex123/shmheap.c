/*************************************
* Lab 4
* Name: Darien Chong
* Student No: A0168214H
* Lab Group: 6
*************************************/

#define SHARED_BETWEEN_PROC 1

#include "shmheap.h"

#include <fcntl.h>
#include <inttypes.h>
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

size_t _shmheap_get_curr_ptr_offset(shmheap_memory_handle mem, shmheap_node *node_ptr) {
	return (char*)node_ptr - (char*)mem.mmap_ptr;
}

/**
 * Returns the offset from this node pointer to the next node pointer.
 * Should only be called if we are guaranteed of the next node pointer's existence.
 */
size_t _shmheap_get_next_ptr_offset(shmheap_node *node_ptr) {
	return sizeof(shmheap_node) + (node_ptr -> size);
}

/** 
 * Returns the next node pointer.
 * Note that we have to cast the pointer to (char*) first, else it increments by sizeof(shmheap_node).
 */
shmheap_node *_shmheap_get_next_ptr(shmheap_node *node_ptr) {
	return (shmheap_node*) (((char*)node_ptr) + _shmheap_get_next_ptr_offset(node_ptr));
}

size_t _shmheap_ptr_subtraction(void* a, void* b) {
	return ((char*) a) - ((char*) b);
}

void *_shmheap_add_offset_to_ptr(void* ptr, size_t offset) {
	return (void*) ((char*)ptr + offset);
}

void *_shmheap_subtract_offset_from_ptr(void* ptr, size_t offset) {
	return (void*) ((char*)ptr - offset);
}

size_t _shmheap_get_heap_size(shmheap_memory_handle mem) {
	return mem.shm_len - sizeof(shmheap_semaphores);
}

/**
 * Does a pass through the entire linked list and performs
 * up to one merge.
 * Returns true if a merge was performed, false otherwise.
 */
bool _shmheap_merge_helper(shmheap_memory_handle mem, shmheap_node *head) {
	shmheap_node *curr_ptr = head;
	shmheap_node *next_ptr = _shmheap_get_next_ptr(curr_ptr);
	size_t heap_size = _shmheap_get_heap_size(mem);
	
	// If the next pointer offset >= heap size, we know we've
	// gone over the limit.
	
	while (_shmheap_get_curr_ptr_offset(mem, curr_ptr) + _shmheap_get_next_ptr_offset(curr_ptr) < heap_size) {
		// Idea: 
		// Check if this partition is empty.
		// - If not empty, then move on.
		// - If empty, check if the next partition is empty.
		//   - If it is, we merge the two partitions (current + next)
		
		if (curr_ptr -> is_filled) {
			curr_ptr = next_ptr;
			next_ptr = _shmheap_get_next_ptr(curr_ptr);
			continue;
		}
		
		if (!(next_ptr -> is_filled)) {
			// Merge the two partitions
			if (is_debug) {
				printf("[_shmheap_merge_helper(%d)]: Merging two partitions, ([%s|%ld] @ [%ld]) and ([%s|%ld] @ [%ld]).\n", 
					getpid(),
					curr_ptr -> is_filled? "T" : "F",
					curr_ptr -> size,
					_shmheap_get_curr_ptr_offset(mem, curr_ptr),
					next_ptr -> is_filled ? "T" : "F",
					next_ptr -> size,
					_shmheap_get_curr_ptr_offset(mem, next_ptr)
				);
				printf("[_shmheap_merge_helper(%d)]: <SANITY CHECK> New partition should be of size [%ld].\n", 
					getpid(),
					(curr_ptr -> size) + sizeof(shmheap_node) + (next_ptr -> size)
				);
			}
			curr_ptr -> size = (curr_ptr -> size) + sizeof(shmheap_node) + (next_ptr -> size);
			
			if (is_debug) {
				printf("[_shmheap_merge_helper(%d)]: New partition = [%s|%ld] @ [%ld].\n",
					getpid(),
					curr_ptr -> is_filled ? "T" : "F",
					curr_ptr -> size,
					_shmheap_get_curr_ptr_offset(mem, curr_ptr)
				);
			}
			return true;
		}
		
		curr_ptr = next_ptr;
		next_ptr = _shmheap_get_next_ptr(curr_ptr);
	}
	
	return false;
}

/**
 * Runs _shmheap_merge_helper in a loop until
 * no more merges detected. This is a separate method
 * to avoid using recursion (to avoid stack overflow for large heaps).
 */ 
void _shmheap_merge(shmheap_memory_handle mem) {
	int merge_iterations = -1;
	bool merge_detected = true;
	shmheap_node *head = mem.mmap_ptr + sizeof(shmheap_semaphores);
	
	while (merge_detected) {
		merge_detected = _shmheap_merge_helper(mem, head);
		merge_iterations++;
	}
	
	if (is_debug) {
		printf("[_shmheap_merge(%d)]: %d merges performed.\n", getpid(), merge_iterations);
	}
	return;
}

/**
 * Returns the first shmheap_node that is empty and has a size large enough
 * to hold an object of size_t size and a bookkeeping section of size sizeof(shmheap_node).
 */
shmheap_node *_shmheap_search_for_first_fit(shmheap_memory_handle mem, size_t size) {
	
	shmheap_node *head_ptr = (shmheap_node*) (mem.mmap_ptr + sizeof(shmheap_semaphores));
	shmheap_node *curr_ptr = head_ptr;
	
	size_t heap_size = _shmheap_get_heap_size(mem);
	size_t current_tally = 0;
	
	// We know when we've traversed the entire list
	// by checking our current tally (every time we pass a node, we increment the tally by (partition size + node size))
	// when this sum = heap size, we've reached the end of the list.
	while (current_tally < heap_size) {
		if (!(curr_ptr -> is_filled) && (curr_ptr -> size >= size)) {
			
			if (is_debug) {
				printf("[_shmheap_search_for_first_fit(%d)]: Found a partition = [%s|%ld] @ [%ld] which is empty with size >= [%ld].\n",
					getpid(),
					curr_ptr -> is_filled ? "T" : "F",
					curr_ptr -> size,
					_shmheap_get_curr_ptr_offset(mem, curr_ptr),
					size
				);
			}
			
			return curr_ptr;
		}
		
		if (is_debug) {
			printf("[_shmheap_search_for_first_fit(%d)]: Current partition status = [%s|%ld] @ [%ld], is either not empty or size < [%ld].\n",
				getpid(),
				curr_ptr -> is_filled ? "T" : "F",
				curr_ptr -> size,
				_shmheap_get_curr_ptr_offset(mem, curr_ptr),
				size
			); 
		}
		curr_ptr = _shmheap_get_next_ptr(curr_ptr);
		current_tally += (sizeof(shmheap_node) + curr_ptr -> size);
	}
	
	// We shouldn't get here, but...
	if (is_debug) {
		printf("[_shmheap_search_for_first_fit(%d)]: Unexpected state encountered.\n", getpid());
	}
	return NULL;
}

/**
 * Rounds up the size to the nearest multiple of 8.
 */
size_t _shmheap_round_up(size_t sz) {
  if (sz == 0) {
    return 0;
  }

  size_t r = sz % 8;
  size_t q = sz / 8;

  return (q + (r == 0 ? 0 : 1)) << 3;
}

void _shmheap_acquire_alloc_mutex(shmheap_memory_handle mem) {
	shmheap_semaphores *sem_ptr = (shmheap_semaphores*) mem.mmap_ptr;
	sem_wait(&(sem_ptr -> alloc_sem));
}

void _shmheap_release_alloc_mutex(shmheap_memory_handle mem) {
	shmheap_semaphores *sem_ptr = (shmheap_semaphores*) mem.mmap_ptr;
	sem_post(&(sem_ptr -> alloc_sem));
}

void _shmheap_acquire_free_mutex(shmheap_memory_handle mem) {
	shmheap_semaphores *sem_ptr = (shmheap_semaphores*) mem.mmap_ptr;
	sem_wait(&(sem_ptr -> free_sem));
}

void _shmheap_release_free_mutex(shmheap_memory_handle mem) {
	shmheap_semaphores *sem_ptr = (shmheap_semaphores*) mem.mmap_ptr;
	sem_post(&(sem_ptr -> free_sem));
}

shmheap_memory_handle shmheap_create(const char *name, size_t len) {
	if (is_debug) {
		printf("[shmheap_create(%d)]: sizeof(size_t) = [%ld].\n", getpid(), sizeof(size_t));
		printf("[shmheap_create(%d)]: shmheap_node size = [%ld].\n", getpid(), sizeof(shmheap_node));
		printf("[shmheap_create(%d)]: shmheap_semaphores size = [%ld].\n", getpid(), sizeof(shmheap_semaphores));
		printf("[shmheap_create(%d)]: heap size = [%ld].\n", getpid(), len);
	}
	
	shmheap_memory_handle mem_handle;
	
	int shm_fd = shm_open(name, O_CREAT | O_RDWR | O_EXCL, 0777);
	
	if (is_debug && shm_fd == -1) {
		printf("[shmheap_create(%d)]: Failed to create shared memory.\n", getpid());
	}
	
	ftruncate(shm_fd, len);
	void *mmap_ptr = mmap(NULL, len, _shmheap_get_prot_permissions(), MAP_SHARED, shm_fd, 0);
	
	// Set up the bookkeeping at the start of the shared memory.
	// Our bookkeeping consists of two mutexes and one node.
	
	shmheap_node head;
	head.is_filled = false;
	head.size = len - (sizeof(shmheap_semaphores) + sizeof(shmheap_node));
	
	shmheap_semaphores semaphores;
	sem_init(&(semaphores.alloc_sem), SHARED_BETWEEN_PROC, 1);
	sem_init(&(semaphores.free_sem), SHARED_BETWEEN_PROC, 1);
	
	void* semaphores_address = mmap_ptr;
	void* node_address = ((char*) mmap_ptr) + sizeof(shmheap_semaphores);
	
	memcpy(semaphores_address, &semaphores, sizeof(shmheap_semaphores));
	memcpy(node_address, &head, sizeof(shmheap_node));
	
	if (is_debug) {
		printf("[shmheap_create(%d)]: Initial bookkeeping node allocated at [%ld].\n", getpid(), _shmheap_ptr_subtraction(node_address, mmap_ptr));
		printf("[shmheap_create(%d)]: <SANITY CHECK> Initial bookkeeping node = [%s|%ld].\n", getpid(), ((shmheap_node*) node_address) -> is_filled ? "T" : "F", ((shmheap_node*) node_address) -> size);
	}
	
	mem_handle.shm_fd = shm_fd;
	mem_handle.mmap_ptr = mmap_ptr;
	mem_handle.shm_len = len;

	return mem_handle;
}

shmheap_memory_handle shmheap_connect(const char *name) {
	shmheap_memory_handle mem_handle;
	
	int shm_fd = shm_open(name, O_RDWR, -1);
	
	if (is_debug && shm_fd == -1) {
		printf("[shmheap_connect(%d)]: Failed to open shared memory.\n", getpid());
	}
	
	struct stat buf;
	fstat(shm_fd, &buf);
	size_t shm_size = buf.st_size;
	void *mmap_ptr = mmap(NULL, shm_size, _shmheap_get_prot_permissions(), MAP_SHARED, shm_fd, 0);
	
	mem_handle.shm_fd = shm_fd;
	mem_handle.mmap_ptr = mmap_ptr;
	mem_handle.shm_len = shm_size;
	
	return mem_handle;
}

void shmheap_disconnect(shmheap_memory_handle mem) {
    int munmap_result = munmap(mem.mmap_ptr, mem.shm_len);
    if (is_debug && munmap_result == -1) {
    	printf("[shmheap_disconnect(%d)]: Failed to unmap shared memory.\n", getpid());
    }
    
    return;
}

void shmheap_destroy(const char *name, shmheap_memory_handle mem) {
	shmheap_semaphores *sem_ptr = (shmheap_semaphores*) mem.mmap_ptr;
	sem_destroy(&(sem_ptr -> alloc_sem));
	sem_destroy(&(sem_ptr -> free_sem));

    int munmap_result = munmap(mem.mmap_ptr, mem.shm_len);
    if (is_debug && munmap_result == -1) {
    	printf("[shmheap_destroy(%d)]: Failed to unmap shared memory.\n", getpid());
    }
    
    shm_unlink(name);
    
    return;
}

void *shmheap_underlying(shmheap_memory_handle mem) {
    return mem.mmap_ptr;
}

void *shmheap_alloc(shmheap_memory_handle mem, size_t sz) {
	size_t node_sz = sizeof(shmheap_node);
	size_t rounded_sz = _shmheap_round_up(sz);
	
	if (is_debug) {
		printf("[shmheap_alloc(%d)]: Acquiring alloc_sem...\n", getpid());
	}
	_shmheap_acquire_alloc_mutex(mem);
	if (is_debug) {
		printf("[shmheap_alloc(%d)]: Acquired alloc_sem.\n", getpid());
		printf("[shmheap_alloc(%d)]: sz = [%ld -(rounded)-> %ld].\n", getpid(), sz, rounded_sz);
	}
	shmheap_node *curr_ptr = _shmheap_search_for_first_fit(mem, sz);
	
	if (is_debug) {
		printf("[shmheap_alloc(%d)]: Found a partition with bookkeeping at [%ld] and data at offset [%ld].\n",
			getpid(),
			_shmheap_get_curr_ptr_offset(mem, curr_ptr),
			_shmheap_get_curr_ptr_offset(mem, _shmheap_add_offset_to_ptr(curr_ptr, node_sz))
		);
	}
	
	// Create a new node
	// - `is_filled` = false
	// - size = current node size - (sz + sizeof(shmheap_node))
	// Modify the current node
	// - Reduce the size.
	// - Set `is_filled` to false.
	// Copy over the new node to the appropriate location
	
	// We have a special case:
	// If the leftover space is less than or equal to the size of bookkeeping, then
	// we should package it with the current node, and NOT make a new tail node
	
	bool is_leftover_space_leq_bookkeeping_size = (curr_ptr -> size - sz) <= sizeof(shmheap_node);
	
	if (is_leftover_space_leq_bookkeeping_size) {
		if (is_debug) {
			printf("[shmheap_alloc(%d)]: Leftover space = [%ld] <= bookkeeping node size = [%ld].\n",
				getpid(),
				curr_ptr -> size - sz,
				sizeof(shmheap_node)
			);
		}
		
		curr_ptr -> is_filled = true;
	} else {
		if (is_debug) {
			printf("[shmheap_alloc(%d)]: Leftover space = [%ld] > bookkeeping node size = [%ld].\n",
				getpid(),
				curr_ptr -> size - sz,
				sizeof(shmheap_node)
			);
		}
		
		shmheap_node new_tail;
		new_tail.is_filled = false;
		new_tail.size = (curr_ptr -> size) - (sz + sizeof(shmheap_node));
		
		curr_ptr -> is_filled = true;
		curr_ptr -> size = sz;
		
		memcpy(_shmheap_get_next_ptr(curr_ptr), &new_tail, node_sz);
	}
		
	_shmheap_release_alloc_mutex(mem);
	
	if (is_debug) {
		printf("[shmheap_alloc(%d)]: Releasing alloc_sem.\n", getpid());
	}
    return _shmheap_add_offset_to_ptr(curr_ptr, node_sz);
}

void shmheap_free(shmheap_memory_handle mem, void *ptr) {
	if (is_debug) {
		printf("[shmheap_free(%d)]: Acquiring free_sem.\n", getpid());
	}
	_shmheap_acquire_free_mutex(mem);
	if (is_debug) {
		shmheap_node *debug_node_ref = (shmheap_node*) (ptr - sizeof(shmheap_node));
		printf("[shmheap_free(%d)]: Acquired free_sem.\n", getpid());
		printf("[shmheap_free(%d)]: ptr offset from mmap_ptr = [%ld].\n", getpid(), _shmheap_ptr_subtraction(ptr, mem.mmap_ptr));
		printf("[shmheap_free(%d)]: Freeing [%s|%ld] at offset [%ld].\n", 
			getpid(), 
			debug_node_ref -> is_filled ? "T" : "F", 
			debug_node_ref -> size, 
			_shmheap_get_curr_ptr_offset(mem, debug_node_ref) + sizeof(shmheap_node)
		);
	}
	
    // Just set `is_filled` to false and run merge
    
    shmheap_node *node_ptr = _shmheap_subtract_offset_from_ptr(ptr, sizeof(shmheap_node));
    node_ptr -> is_filled = false;
    
    _shmheap_merge(mem);
    
    _shmheap_release_free_mutex(mem);
    if (is_debug) {
		printf("[shmheap_free(%d)]: Releasing free_sem.\n", getpid());
	}
    return;
}

shmheap_object_handle shmheap_ptr_to_handle(shmheap_memory_handle mem, void *ptr) {
	size_t offset = _shmheap_ptr_subtraction(ptr, mem.mmap_ptr);
	
	shmheap_object_handle obj_handle;
	obj_handle.offset = offset;
	
	return obj_handle;
}

void *shmheap_handle_to_ptr(shmheap_memory_handle mem, shmheap_object_handle hdl) {
    void *ptr = _shmheap_add_offset_to_ptr(mem.mmap_ptr, hdl.offset);
    return ptr;
}
