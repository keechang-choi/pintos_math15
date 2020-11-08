#ifndef SUP_PAGE
#define SUP_PAGE
#include <hash.h>

struct sup_table_entry{
    void* uaddr;
    bool writable;
    bool is_loaded;
    struct file* file;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    struct hash_elem sup_elem;
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

#endif