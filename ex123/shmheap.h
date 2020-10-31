/*************************************
* Lab 4
* Name: Darien Chong
* Student No: A0168214H
* Lab Group: 6
*************************************/

#include <stddef.h>
#include <stdbool.h>
#include <semaphore.h>

/*
You should modify these structs to suit your implementation,
but remember that all the functions declared here must have
a signature that is callable using the APIs specified in the
lab document.

You may define other helper structs or convert the existing
structs to typedefs, as long as the functions satisfy the
requirements in the lab document.  If you declare additional names (helper structs or helper functions), they should be prefixed with "shmheap_" to avoid potential name clashes.
*/

typedef struct {
	// const char *name; // The name of the shared heap.
	int shm_fd; // The file descriptor of the shared heap.
	void *mmap_ptr; // The pointer returned by mmap.
	int shm_len; // The length of the heap.

	int alloc_size; // The length of the allocation.
} shmheap_memory_handle;

typedef struct {
	int offset; // Offset from base address
} shmheap_object_handle;

typedef struct {
	bool is_filled; // Whether the current space is filled
	int offset_to_next; // Offset to the next node
	size_t size; // Size of partition
	
	// offset_to_next fulfills 
	// ptr_to_next = &shmheap_node + offset_to_next
} shmheap_node;

typedef struct {
	sem_t alloc_sem; // Controls access to alloc
	sem_t free_sem; // Controls access to free
} shmheap_semaphores;

/*
These functions form the public API of your shmheap library.
*/

shmheap_memory_handle shmheap_create(const char *name, size_t len);
shmheap_memory_handle shmheap_connect(const char *name);
void shmheap_disconnect(shmheap_memory_handle mem);
void shmheap_destroy(const char *name, shmheap_memory_handle mem);
void *shmheap_underlying(shmheap_memory_handle mem);
void *shmheap_alloc(shmheap_memory_handle mem, size_t sz);
void shmheap_free(shmheap_memory_handle mem, void *ptr);
shmheap_object_handle shmheap_ptr_to_handle(shmheap_memory_handle mem, void *ptr);
void *shmheap_handle_to_ptr(shmheap_memory_handle mem, shmheap_object_handle hdl);
