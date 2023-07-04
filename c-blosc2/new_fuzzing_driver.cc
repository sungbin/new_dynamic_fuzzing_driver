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

#define MAX_API_SEQ_LEN 8
#define DEFINED_API_BLOCK_N 10
#define BANK_EACH_OBJ_LEN 4

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
int api_10 (FuzzedDataProvider& provider);

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
  
  for (int i = 0; i < api_seq_len; i++) {

     size_t selected = (size_t) provider.ConsumeIntegralInRange<uint8_t>(0, DEFINED_API_BLOCK_N);

     
     int ret;
     switch (selected) {
     case 0:
       ret = api_0(provider);
       if (ret == -1) return 0;
       break;

     case 1:
       ret = api_1(provider);
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

     case 4:
       ret = api_4(provider);
       if (ret == -1) return 0;
       break;

     case 5:
       ret = api_5(provider);
       if (ret == -1) return 0;
       break;

     case 6:
       ret = api_6(provider);
       if (ret == -1) return 0;
       break;

     case 7:
       ret = api_7(provider);
       if (ret == -1) return 0;
       break;

     case 8:
       ret = api_8(provider);
       if (ret == -1) return 0;
       break;

     case 9:
       ret = api_9(provider);
       if (ret == -1) return 0;
       break;

     case 10:
       ret = api_10(provider);
       if (ret == -1) return 0;
       break;

     }
     DEBUG_PRINT(("-%zu-", selected));

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

// Constructor : blosc2_storage
int api_0 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  blosc2_storage *obj_0 =(blosc2_storage*)malloc(sizeof(blosc2_storage));
  bool input_1 = provider.ConsumeBool();

  blosc2_storage storage = {.contiguous=input_1};
  memcpy(obj_0, &storage, sizeof(blosc2_storage));

  obj_storages[obj_0_idx] = obj_0;
  return 0;
}

// Desctructor : blosc2_storage
int api_1 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  blosc2_storage *obj_0 = obj_storages[obj_0_idx];

  free(obj_0);
  obj_storages[obj_0_idx] = 0x0;

  return 0;
}

// Constructor : Cframe
int api_2 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);


  obj_Cframes[obj_0_idx] = (blosc2_Cframe*)malloc(sizeof(blosc2_Cframe));
  return 0;
}

// Destructor : Cframe
int api_3 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  blosc2_Cframe *obj_0 = obj_Cframes[obj_0_idx];
  free(obj_0);
  obj_Cframes[obj_0_idx] = 0x0;

  return 0;
}


// Constructor : blosc2_schunk
int api_4 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_storage *obj_0 = obj_storages[obj_0_idx];
  obj_schunks[obj_1_idx] = blosc2_schunk_new(obj_0);


  return 0;
}

// Destructor : blosc2_schunk
int api_5 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  blosc2_schunk_free(obj_0);
  obj_schunks[obj_0_idx] = 0x0;

  return 0;
}

// blosc2_schunk_append_buffer()
int api_6 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int input_1_size = (int) provider.ConsumeIntegralInRange<uint8_t>(0, 200);
  char *input_1 = (char*)malloc(sizeof(char)*input_1_size);
  memcpy((void*)input_1, reinterpret_cast<void*>(provider.ConsumeBytes<uint8_t>(input_1_size).data()), input_1_size);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];
  blosc2_schunk_append_buffer(obj_0, input_1, input_1_size);

  _garbages->items[_garbages->size] = input_1;
  _garbages->size++;

  return 0;
}

// blosc2_schunk_to_buffer()
int api_7 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];
  blosc2_Cframe *obj_1 = obj_Cframes[obj_1_idx];

  bool cframe_needs_free;
  int64_t length = blosc2_schunk_to_buffer(obj_0, &(obj_1->cframe), &cframe_needs_free);
  if (cframe_needs_free) {
      _garbages->items[_garbages->size]=obj_1->cframe;
      _garbages->size++;
  }

  obj_1->len = length;

  return 0;
}


int api_8 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  blosc2_Cframe *obj_0 = obj_Cframes[obj_0_idx];
  bool input_2 = provider.ConsumeBool();

  obj_schunks[obj_1_idx] = blosc2_schunk_from_buffer(obj_0->cframe, obj_0->len, input_2);
  if (input_2) {
    _garbages->items[_garbages->size]=obj_0->cframe;
    _garbages->size++;
  }

}

// blosc2_schunk_to_file(), blosc2_schunk_open()
int api_9 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];
  blosc2_schunk *obj_1 = obj_schunks[obj_1_idx];

  blosc2_schunk_to_file(obj_0, ".test_file.b2frame");
  obj_1 = blosc2_schunk_open(".test_file.b2frame");
  remove(".test_file.b2frame");

  return 0;
}


// blosc2_schunk_decompress_chunk()
int api_10 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int input_1 = (int) provider.ConsumeIntegralInRange<uint8_t>(0, 200);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  char buf[1000];
  blosc2_schunk_decompress_chunk(obj_0, input_1, buf, 1000);

  return 0;
}
