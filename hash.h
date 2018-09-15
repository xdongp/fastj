#ifndef  _H3_HASH_H__
#define  _H3_HASH_H__

struct elem_s {
    int chance;
    int match;
    int platform;
    char domain[32];
    char path[480]; /* max_url_len=480 */
    char redirect[480]; /* max_url_len=480 */
    struct elem_s *next; 
};

typedef struct elem_s elem_t;

struct entry_s {
    char *key;
    elem_t *value;
    struct entry_s *next;
};

typedef struct entry_s entry_t;


struct hashtable_s {
    int size;
    struct entry_s **table; 
};

typedef struct hashtable_s hashtable_t;

/* create hashtable */
hashtable_t *ht_create( int size );

/* Hash a string for a particular hash table. */
int ht_hash( hashtable_t *hashtable, char *key );

/* Create a key-value pair. */
entry_t *ht_newpair( char *key, elem_t *value );

/* Insert a key-value pair into a hash table. */
void ht_set( hashtable_t *hashtable, char *key, elem_t *value);

/* add data into hash entry */
void ht_set_data( hashtable_t *hashtable, char *key, elem_t *value);

/* Retrieve a key-value pair from a hash table. */
elem_t *ht_get( hashtable_t *hashtable, char *key );

/* List a hash table. */
void ht_list(hashtable_t *hashtable);

/* print  elem_t */
void print_elem(elem_t *elem);

/* clear hash table, not destroy it */
void ht_clear(hashtable_t *hashtable);

#endif
