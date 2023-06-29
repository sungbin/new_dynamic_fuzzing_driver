#include "blosc2.h"
#include <cstdint>
#include <cstddef>
#include <string>

#ifdef DEBUG
# define DEBUG_PRINT(x) printf x; \
	fflush(stdout)
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif

#ifdef DEBUG
# define DEBUG_PRINT_ARRAY(_arr, _size) \
	printf("["); \
	for (int i = 0; i < _size; i++) \
	    printf("%d ", _arr[i]); \
	printf("\b]\n")
#else
# define DEBUG_PRINT_ARRAY(_arr, _size) do {} while (0)
#endif

#define MAX_API_SEQ_LEN 4
#define DEFINED_API_BLOCK_N 4
#define BANK_EACH_OBJ_LEN 2

typedef struct garbages {
    void *items[1000];
    int size = 0;
} garbages;

garbages *_garbages;

typedef struct blosc2_Cframe {
    uint8_t *cframe;
    long len;
} blosc2_Cframe;


blosc2_storage * obj_storages[BANK_EACH_OBJ_LEN];
blosc2_schunk * obj_schunks[BANK_EACH_OBJ_LEN];
blosc2_Cframe * obj_Cframes[BANK_EACH_OBJ_LEN];

int api_0 ();
int api_1 ();
int api_4 ();
int api_5 ();

int main (int argc, char *argv[]) {

  // Initialize global var for global scopes
  {
    _garbages = (garbages*)malloc(sizeof(garbages));
    _garbages->size = 0;

    if (access(".test_file.b2frame", F_OK) == 0) {
        remove(".test_file.b2frame");
    }

    blosc2_init();

    memset(obj_storages, 0, sizeof(void*) * BANK_EACH_OBJ_LEN);
    memset(obj_schunks, 0, sizeof(void*) * BANK_EACH_OBJ_LEN);
    memset(obj_Cframes, 0, sizeof(void*) * BANK_EACH_OBJ_LEN);
  
  }

  size_t api_seq_len = 4;
  DEBUG_PRINT(("DEBUG: API sequence length: %zu \n", api_seq_len));

  for (int i = 0; i < api_seq_len; i++) {

     int ret;
     switch (i) {
     case 0:
       ret = api_0();
       if (ret == -1) return 0;
       break;

     case 1:
       ret = api_4();
       if (ret == -1) return 0;
       break;

     case 2:
       ret = api_5();
       if (ret == -1) return 0;
       break;

     case 3:
       ret = api_1();
       if (ret == -1) return 0;
       break;

     }
  }

  // Destruct vars for global scope
  {
    for (int i = 0; i < BANK_EACH_OBJ_LEN; i++) {
      if (obj_storages[i] != 0x0) {
        free(obj_storages[i]);
        free(obj_schunks[i]);
        free(obj_Cframes[i]);
      }
    }

    blosc2_destroy();

    for (int i = 0; i < _garbages->size; i++)
      free(_garbages->items[i]);
    free(_garbages);
  }

  return 0;
}

// blosc2_storage * obj_storages[BANK_EACH_OBJ_LEN];
// blosc2_schunk * obj_schunks[BANK_EACH_OBJ_LEN];
// Cframe * obj_Cframes[BANK_EACH_OBJ_LEN];


// Constructor : blosc2_storage
int api_0 () {
  DEBUG_PRINT(("DEBUG:\t RUN (Constructor : blosc2_storage) "));

  int obj_0_idx = 0;
  blosc2_storage *obj_0 =(blosc2_storage*)malloc(sizeof(blosc2_storage));
  bool input_1 = 0;

  DEBUG_PRINT((" -- : obj_0_idx: %d, input_1: %d \n", obj_0_idx, input_1));
  DEBUG_PRINT(("DEBUG: \t\t\t p0: %p \n", obj_0));

  // Prevent memory leaks (duplicated allocations)
  //if (0x0 !=(void*)obj_0) return -1;

  DEBUG_PRINT(("DEBUG:\t\t blosc2_storage(Storages[%d], %d) \n", obj_0_idx, input_1));
  blosc2_storage storage = {.contiguous=input_1};
  //obj_0 = (blosc2_storage*)malloc(sizeof(blosc2_storage));
  memcpy(obj_0, &storage, sizeof(blosc2_storage));


  obj_storages[obj_0_idx] = obj_0;

  DEBUG_PRINT(("DEBUG:\t DONE (Constructor : blosc2_storage) \n"));
  return 0;
}

// Desctructor : blosc2_storage
int api_1 () {
  DEBUG_PRINT(("DEBUG:\t RUN (Desctructor : blosc2_storage) "));

  int obj_0_idx = 0;
  blosc2_storage *obj_0 = obj_storages[obj_0_idx];

  DEBUG_PRINT((" -- : obj_0_idx: %d \n", obj_0_idx));

  //if (0x0 ==(void*)obj_0) return -1;

  DEBUG_PRINT(("DEBUG:\t\t ~blosc2_storage(Storages[%d]) \n", obj_0_idx));
  free(obj_0);
  //obj_0 = 0x0;
  obj_storages[obj_0_idx] = 0x0;

  DEBUG_PRINT(("DEBUG:\t DONE (Desctructor : blosc2_storage) \n"));
  return 0;
}

// Constructor : blosc2_schunk
int api_4 () {
  DEBUG_PRINT(("DEBUG:\t RUN (Constructor : blosc2_schunk) "));

  int obj_0_idx = 0;
  int obj_1_idx = 0;

  blosc2_storage *obj_0 = obj_storages[obj_0_idx];
  blosc2_schunk *obj_1 = obj_schunks[obj_1_idx];

  DEBUG_PRINT(("DEBUG: \t\t\t p1: %p \n", obj_0));
  DEBUG_PRINT(("DEBUG: \t\t\t p2: %p \n", obj_1));

  DEBUG_PRINT((" -- obj_0_idx: %d, obj_1_idx: %d \n", obj_0_idx, obj_1_idx));

  // Prevent memory leaks (duplicated allocations)
  //if (0x0 ==(void*)obj_0) return -1;
  //if (0x0 !=(void*)obj_1) return -1;
  
  DEBUG_PRINT(("DEBUG:\t\t blosc2_schunk(Cframes[%d]) \n", obj_0_idx));
  obj_1 = blosc2_schunk_new(obj_0);

  DEBUG_PRINT(("DEBUG:\t DONE (Constructor : blosc2_schunk) \n"));
  return 0;
}

// Destructor : blosc2_schunk
int api_5 () {
  DEBUG_PRINT(("DEBUG:\t RUN (Destructor : blosc2_schunk) "));

  int obj_0_idx = 0;

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  DEBUG_PRINT((" -- obj_0_idx: %d \n", obj_0_idx));

  // Prevent memory leaks (duplicated allocations)
  //if (0x0 ==(void*)obj_0) return -1;
  
  DEBUG_PRINT(("DEBUG:\t\t ~blosc2_schunk(Schunks[%d]) \n", obj_0_idx));
  free(obj_0);
  //obj_0 = 0x0;
  obj_schunks[obj_0_idx] = 0x0;

  DEBUG_PRINT(("DEBUG:\t DONE (Destructor : blosc2_schunk) \n"));
  return 0;
}

