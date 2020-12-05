#ifndef SUP_PAGE
#define SUP_PAGE
#include <hash.h>

#define NORMAL 1
#define MMAP_FILE 2
#define SWAP 3

struct lock sup_lock;
struct sup_table_entry{
    int type;

    void* uaddr;
    bool writable;
    bool is_loaded;
    struct file* file;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    struct hash_elem sup_elem;
    struct list_elem m_sup_elem;

    int swap_index;
};
void sup_table_init(struct hash* sup_table);
int sup_val(struct hash_elem* hash, void* aux);
bool sup_less(struct hash_elem* a, struct hash_elem* b, void* aux);
bool sup_insert(struct hash* sup_table, struct sup_table_entry* sup_entry);
bool sup_delete(struct hash* sup_table, struct sup_table_entry* sup_entry);
struct sup_table_entry* sup_find_entry(struct hash* sup_table, void* uaddr);
void sup_destroy_func(struct hash_elem* h, void* aux);
void sup_table_destroy(struct hash* sup_table);

bool sup_load_file(void* kaddr, struct sup_table_entry* sup_entry);


struct mmap_entry{
    int mapid;
    struct list sup_entry_list;
    struct file* file;
    struct list_elem mmap_elem;
};

bool mmap_create_sup_entries(struct mmap_entry* mmap_entry, void* addr);
void mmap_delete_sup_list(struct mmap_entry* mmap_entry, struct hash*);
#endif
