#include "blosc2.h"
#include <cstdint>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
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

int table[MAX_API_SEQ_LEN] = {0, };

typedef struct garbages {
    void *items[1000];
    int size = 0;
} garbages;

garbages *_garbages;

typedef struct blosc2_Cframe {
    uint8_t *cframe;
    long len;
} blosc2_Cframe;

void assert_empty (void *obj) {
  if (obj == 0x0) {
    __builtin_trap();
  }
}

void assert_filled (void *obj) {
  if (obj != 0x0) {
    __builtin_trap();
  }
}

blosc2_storage * obj_storages[BANK_EACH_OBJ_LEN];
blosc2_schunk * obj_schunks[BANK_EACH_OBJ_LEN];
blosc2_Cframe * obj_Cframes[BANK_EACH_OBJ_LEN];

int api_0 (FuzzedDataProvider& provider);
int api_1 (FuzzedDataProvider& provider);
int api_2 (FuzzedDataProvider& provider);
int api_3 (FuzzedDataProvider& provider);
int api_4 (FuzzedDataProvider& provider);
int api_5 (FuzzedDataProvider& provider);
int api_6 (FuzzedDataProvider& provider);
int api_7 (FuzzedDataProvider& provider);
int api_8 (FuzzedDataProvider& provider);
int api_9 (FuzzedDataProvider& provider);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

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
  FuzzedDataProvider provider(data, size);


  size_t api_seq_len = (size_t) provider.ConsumeIntegralInRange<uint8_t>(1, MAX_API_SEQ_LEN);
  //size_t api_seq_len = 4;
  DEBUG_PRINT(("DEBUG: API sequence length: %zu \n", api_seq_len));

  
  for (int i = 0; i < api_seq_len; i++) {

     size_t selected = (size_t) provider.ConsumeIntegralInRange<uint8_t>(0, DEFINED_API_BLOCK_N);
     DEBUG_PRINT(("DEBUG: Selected API index %zu \n", selected));

     if (i == selected) table[i] = 1;
     
     int ret;
     switch (selected) {
     case 0:
       ret = api_0(provider);
       if (ret == -1) return 0;
       break;

     case 1:
       ret = api_4(provider);
       if (ret == -1) return 0;
       break;

     case 2:
       ret = api_2(provider);
       if (ret == -1) return 0;
       break;

     case 3:
       ret = api_3(provider);
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

  if (table[0] && table[1] && table[2] && table[3]) {
	  for (int i = 0; i < 1000; i++)
		  printf("@@@@@@");
	  __builtin_trap();
  }

  return 0;
}

// blosc2_storage * obj_storages[BANK_EACH_OBJ_LEN];
// blosc2_schunk * obj_schunks[BANK_EACH_OBJ_LEN];
// Cframe * obj_Cframes[BANK_EACH_OBJ_LEN];


// Constructor : blosc2_storage
int api_0 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN (Constructor : blosc2_storage) "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  blosc2_storage *obj_0 =(blosc2_storage*)malloc(sizeof(blosc2_storage));
  bool input_1 = provider.ConsumeBool();

  DEBUG_PRINT((" -- : obj_0_idx: %d, input_1: %d \n", obj_0_idx, input_1));

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
int api_1 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN (Desctructor : blosc2_storage) "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
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

// Constructor : Cframe
int api_2 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN (Constructor : Cframe) "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  blosc2_Cframe *obj_0 = obj_Cframes[obj_0_idx];

  DEBUG_PRINT((" -- : obj_0_idx: %d \n", obj_0_idx));

  // Prevent memory leaks (duplicated allocations)
  if (0x0 !=(void*)obj_0) return -1;

  DEBUG_PRINT(("DEBUG:\t\t Cframe(Cframes[%d]) \n", obj_0_idx));
  obj_0 = (blosc2_Cframe*)malloc(sizeof(blosc2_Cframe));

  DEBUG_PRINT(("DEBUG:\t DONE (Constructor : Cframe) \n"));
  return 0;
}

// Destructor : Cframe
int api_3 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN (Destructor : Cframe) "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  blosc2_Cframe *obj_0 = obj_Cframes[obj_0_idx];

  DEBUG_PRINT((" -- : obj_0_idx: %d \n", obj_0_idx));

  if (0x0 ==(void*)obj_0) return -1;

  DEBUG_PRINT(("DEBUG:\t\t ~Cframe(Cframes[%d]) \n", obj_0_idx));
  free(obj_0);

  DEBUG_PRINT(("DEBUG:\t DONE (Destructor : Cframe) \n"));
  return 0;
}


// Constructor : blosc2_schunk
int api_4 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN (Constructor : blosc2_schunk) "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_storage *obj_0 = obj_storages[obj_0_idx];
  blosc2_schunk *obj_1 = obj_schunks[obj_1_idx];

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
int api_5 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN (Destructor : blosc2_schunk) "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  DEBUG_PRINT((" -- obj_0_idx: %d \n", obj_0_idx));

  // Prevent memory leaks (duplicated allocations)
  if (0x0 ==(void*)obj_0) return -1;
  
  DEBUG_PRINT(("DEBUG:\t\t ~blosc2_schunk(Schunks[%d]) \n", obj_0_idx));
  free(obj_0);
  //obj_0 = 0x0;
  obj_schunks[obj_0_idx] = 0x0;

  DEBUG_PRINT(("DEBUG:\t DONE (Destructor : blosc2_schunk) \n"));
  return 0;
}

// blosc2_schunk_append_buffer()
int api_6 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN blosc2_schunk_append_buffer() "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int input_1_size = (int) provider.ConsumeIntegralInRange<uint8_t>(0, 200);
  char *input_1 = (char*)malloc(sizeof(char)*input_1_size);
  memcpy((void*)input_1, reinterpret_cast<void*>(provider.ConsumeBytes<uint8_t>(input_1_size).data()), input_1_size);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  DEBUG_PRINT((" -- obj_0_idx: %d, input_1_size: %d - ", obj_0_idx, input_1_size));
  DEBUG_PRINT_ARRAY(input_1, input_1_size);

  if (0x0 ==(void*)obj_0) return -1;
  
  DEBUG_PRINT(("DEBUG:\t\t blosc2_schunk_append_buffer(Schunks[%d], Array) \n", obj_0_idx));
  blosc2_schunk_append_buffer(obj_0, input_1, input_1_size);

  _garbages->items[_garbages->size] = input_1;
  _garbages->size++;

  DEBUG_PRINT(("DEBUG:\t DONE blosc2_schunk_append_buffer() \n"));
  return 0;
}

// blosc2_schunk_to_buffer()
int api_7 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN blosc2_schunk_to_buffer() "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];
  blosc2_Cframe *obj_1 = obj_Cframes[obj_0_idx];

  DEBUG_PRINT((" -- obj_0_idx: %d, obj_1_idx: %d \n", obj_0_idx, obj_1_idx));

  if (0x0 ==(void*)obj_0) return -1;
  if (0x0 ==(void*)obj_1) return -1;
  
  DEBUG_PRINT(("DEBUG:\t\t blosc2_schunk_to_buffer(Schunks[%d], Cframes[%d]) \n", obj_0_idx, obj_1_idx));
  bool cframe_needs_free;
  int64_t length = blosc2_schunk_to_buffer(obj_0, &(obj_1->cframe), &cframe_needs_free);
  if (cframe_needs_free) {
      _garbages->items[_garbages->size]=obj_1->cframe;
      _garbages->size++;
  }

  obj_1->len = length;

  DEBUG_PRINT(("DEBUG:\t DONE blosc2_schunk_to_buffer() \n"));
  return 0;
}

// blosc2_schunk_to_file(), blosc2_schunk_open()
int api_8 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN blosc2_schunk_to_file(), blosc2_schunk_open() "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  // obj_0_idx can be equal with obj_1_idx
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];
  blosc2_schunk *obj_1 = obj_schunks[obj_1_idx];

  DEBUG_PRINT((" -- obj_0_idx: %d, obj_1_idx: %d \n", obj_0_idx, obj_1_idx));

  if (0x0 ==(void*)obj_0) return -1;
  if (0x0 !=(void*)obj_1) return -1;
  
  DEBUG_PRINT(("DEBUG:\t\t merged(Schunks[%d], Schunks[%d]) \n", obj_0_idx, obj_1_idx));
  blosc2_schunk_to_file(obj_0, ".test_file.b2frame");
  obj_1 = blosc2_schunk_open(".test_file.b2frame");
  remove(".test_file.b2frame");

  DEBUG_PRINT(("DEBUG:\t DONE blosc2_schunk_to_file(), blosc2_schunk_open() \n"));
  return 0;
}


// blosc2_schunk_decompress_chunk()
int api_9 (FuzzedDataProvider& provider) {
  DEBUG_PRINT(("DEBUG:\t RUN blosc2_schunk_decompress_chunk() "));

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int input_1 = (int) provider.ConsumeIntegralInRange<uint8_t>(0, 200);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  DEBUG_PRINT((" -- obj_0_idx: %d, input_1_size: %d - ", obj_0_idx, 200));
  if (0x0 ==(void*)obj_0) return -1;

  DEBUG_PRINT(("DEBUG:\t\t blosc2_schunk_decompress_chunk(Schunks[%d]) \n", obj_0_idx));
  char buf[1000];
  blosc2_schunk_decompress_chunk(obj_0, input_1, buf, 1000);

  DEBUG_PRINT(("DEBUG:\t DONE blosc2_schunk_decompress_chunk() \n"));
  return 0;
}
