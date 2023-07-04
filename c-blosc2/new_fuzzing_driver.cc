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

#define MAX_API_SEQ_LEN 20
#define DEFINED_API_BLOCK_N 13
#define BANK_EACH_OBJ_LEN 4

#define CHUNKSIZE (200 * 1000)

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

//blosc2_storage * obj_storages[BANK_EACH_OBJ_LEN];
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
int api_11 (FuzzedDataProvider& provider);
int api_12 (FuzzedDataProvider& provider);
int api_13 (FuzzedDataProvider& provider);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

  // Initialize global var for global scopes
  {
    _garbages = (garbages*)malloc(sizeof(garbages));
    _garbages->size = 0;

    if (access(".test_file.b2frame", F_OK) == 0) {
        remove(".test_file.b2frame");
    }

    blosc2_init();

    //memset(obj_storages, 0, sizeof(void*) * BANK_EACH_OBJ_LEN);
    memset(obj_schunks, 0, sizeof(void*) * BANK_EACH_OBJ_LEN);
    memset(obj_Cframes, 0, sizeof(void*) * BANK_EACH_OBJ_LEN);
  
  }
  FuzzedDataProvider provider(data, size);


  size_t api_seq_len = (size_t) provider.ConsumeIntegralInRange<uint8_t>(1, MAX_API_SEQ_LEN);
  DEBUG_PRINT(("uint8_t: %zu(Base: 1) \n", api_seq_len));

  
  for (int i = 0; i < api_seq_len; i++) {

     size_t selected = (size_t) provider.ConsumeIntegralInRange<uint8_t>(0, DEFINED_API_BLOCK_N);
     DEBUG_PRINT(("uint8_t: %zu (API selected) \n", selected));

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

     case 11:
       ret = api_11(provider);
       if (ret == -1) return 0;
       break;

     case 12:
       ret = api_12(provider);
       if (ret == -1) return 0;
       break;

     case 13:
       ret = api_13(provider);
       if (ret == -1) return 0;
       break;

     }
  }

  // Destruct vars for global scope
  {
    for (int i = 0; i < BANK_EACH_OBJ_LEN; i++) {
      if (obj_schunks[i] != 0x0) {
        free(obj_schunks[i]);
      }
      if (obj_Cframes[i] != 0x0) {
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

// Constructor : Cframe
int api_0 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));

  obj_Cframes[obj_0_idx] = (blosc2_Cframe*)malloc(sizeof(blosc2_Cframe));

  return 0;
}

// Destructor : Cframe
int api_1 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_Cframe *obj_0 = obj_Cframes[obj_0_idx];

  free(obj_0);
  obj_Cframes[obj_0_idx] = 0x0;

  return 0;
}



// Constructor : blosc2_schunk
int api_2 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 =(blosc2_schunk*)malloc(sizeof(blosc2_storage));
  bool input_1 = provider.ConsumeBool();
  DEBUG_PRINT(("bool: %d\n", input_1));

  blosc2_storage *pstorage = (blosc2_storage*)malloc(sizeof(blosc2_storage));
  blosc2_storage storage = {.contiguous=input_1};
  memcpy(pstorage, &storage, sizeof(blosc2_storage));

  obj_0 = blosc2_schunk_new(pstorage);
  _garbages->items[_garbages->size] = pstorage;
  _garbages->size ++;

  obj_schunks[obj_0_idx] = obj_0;
  return 0;
}

// Destructor : blosc2_schunk
int api_3 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  free(obj_0);
  obj_schunks[obj_0_idx] = 0x0;

  return 0;
}



// blosc2_schunk_append_buffer (1)
int api_4 (FuzzedDataProvider& provider) {
  int nchunks = 0;

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));

  bool input_1 = provider.ConsumeBool();
  DEBUG_PRINT(("bool: %d\n", input_1));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t *data = (int32_t*)malloc(isize);
  int32_t *data_zeros = (int32_t*)calloc(CHUNKSIZE, sizeof(int32_t));
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    if (input_1 && nchunk >= 2) {
      blosc2_schunk_append_buffer(obj_0, data_zeros, isize);
    }
    else {
      for (int i = 0; i < CHUNKSIZE; i++) {
        data[i] = i + nchunk * CHUNKSIZE;
      }
      blosc2_schunk_append_buffer(obj_0, data, isize);
    }
  }

  _garbages->items[_garbages->size] = data;
  _garbages->size ++;
  _garbages->items[_garbages->size] = data_zeros;
  _garbages->size ++;

  return 0;
}

// blosc2_schunk_append_buffer (2)
int api_5 (FuzzedDataProvider& provider) {
  int nchunks = 1;

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  bool input_1 = provider.ConsumeBool();
  DEBUG_PRINT(("bool: %d\n", input_1));

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t *data = (int32_t*)malloc(isize);
  int32_t *data_zeros = (int32_t*)calloc(CHUNKSIZE, sizeof(int32_t));
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    if (input_1 && nchunk >= 2) {
      blosc2_schunk_append_buffer(obj_0, data_zeros, isize);
    }
    else {
      for (int i = 0; i < CHUNKSIZE; i++) {
        data[i] = i + nchunk * CHUNKSIZE;
      }
      blosc2_schunk_append_buffer(obj_0, data, isize);
    }
  }

  _garbages->items[_garbages->size] = data;
  _garbages->size ++;
  _garbages->items[_garbages->size] = data_zeros;
  _garbages->size ++;

  return 0;
}

// blosc2_schunk_append_buffer (3)
int api_6 (FuzzedDataProvider& provider) {
  int nchunks = 5;

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  bool input_1 = provider.ConsumeBool();
  DEBUG_PRINT(("bool: %d\n", input_1));

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t *data = (int32_t*)malloc(isize);
  int32_t *data_zeros = (int32_t*)calloc(CHUNKSIZE, sizeof(int32_t));
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    if (input_1 && nchunk >= 2) {
      blosc2_schunk_append_buffer(obj_0, data_zeros, isize);
    }
    else {
      for (int i = 0; i < CHUNKSIZE; i++) {
        data[i] = i + nchunk * CHUNKSIZE;
      }
      blosc2_schunk_append_buffer(obj_0, data, isize);
    }
  }

  _garbages->items[_garbages->size] = data;
  _garbages->size ++;
  _garbages->items[_garbages->size] = data_zeros;
  _garbages->size ++;

  return 0;
}

// blosc2_schunk_append_buffer (4)
int api_7 (FuzzedDataProvider& provider) {
  int nchunks = 10;

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  bool input_1 = provider.ConsumeBool();
  DEBUG_PRINT(("bool: %d\n", input_1));

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t *data = (int32_t*)malloc(isize);
  int32_t *data_zeros = (int32_t*)calloc(CHUNKSIZE, sizeof(int32_t));
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    if (input_1 && nchunk >= 2) {
      blosc2_schunk_append_buffer(obj_0, data_zeros, isize);
    }
    else {
      for (int i = 0; i < CHUNKSIZE; i++) {
        data[i] = i + nchunk * CHUNKSIZE;
      }
      blosc2_schunk_append_buffer(obj_0, data, isize);
    }
  }

  _garbages->items[_garbages->size] = data;
  _garbages->size ++;
  _garbages->items[_garbages->size] = data_zeros;
  _garbages->size ++;

  return 0;
}
//
  //  //  //
  //  
  /*
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];
  Cframe *obj_1 = obj_Cframe[obj_1_idx];
  */

// blosc2_schunk_to_buffer()
int api_8 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  int obj_1_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_1_idx));
  bool input_2 = provider.ConsumeBool();
  DEBUG_PRINT(("bool: %d\n", input_2));

  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];
  blosc2_Cframe *obj_1 = obj_Cframes[obj_1_idx];

  bool cframe_needs_free;
  obj_1->len = blosc2_schunk_to_buffer(obj_0, &(obj_1->cframe), &cframe_needs_free);
  if (cframe_needs_free) {
      _garbages->items[_garbages->size]=obj_1->cframe;
      _garbages->size++;
  }

  return 0;
}

// blosc2_schunk_from_buffer()
int api_9 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_Cframe *obj_0 = obj_Cframes[obj_0_idx];
  bool input_1 = provider.ConsumeBool();
  DEBUG_PRINT(("bool: %d\n", input_1));

  blosc2_schunk* schunk;
  blosc2_schunk* schunk2 = blosc2_schunk_from_buffer(obj_0->cframe, obj_0->len, input_1);

  if (! input_1) {
    blosc2_schunk_to_file(schunk2, "test_file.b2frame");
  }

  if (! input_1) {
    blosc2_schunk_free(schunk2);
    schunk = blosc2_schunk_open("test_file.b2frame");
  }
  else {
    schunk = schunk2;
  }
  blosc2_schunk_free(schunk);
  
  return 0;
}

// blosc2_schunk_to_file(), blosc2_schunk_open()
int api_10 (FuzzedDataProvider& provider) {
  int nchunks = 0;

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t *data_dest = (int32_t*)malloc(isize);
  for (int nchunk = 0; nchunk < nchunks; nchunk++)
    blosc2_schunk_decompress_chunk(obj_0, nchunk, (void *) data_dest, isize);

  _garbages->items[_garbages->size]=data_dest;
  _garbages->size++;

  return 0;
}

// blosc2_schunk_to_file(), blosc2_schunk_open()
int api_11 (FuzzedDataProvider& provider) {
  int nchunks = 1;

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t *data_dest = (int32_t*)malloc(isize);
  for (int nchunk = 0; nchunk < nchunks; nchunk++)
    blosc2_schunk_decompress_chunk(obj_0, nchunk, (void *) data_dest, isize);

  _garbages->items[_garbages->size]=data_dest;
  _garbages->size++;

  return 0;
}

// blosc2_schunk_to_file(), blosc2_schunk_open()
int api_12 (FuzzedDataProvider& provider) {
  int nchunks = 5;

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t *data_dest = (int32_t*)malloc(isize);
  for (int nchunk = 0; nchunk < nchunks; nchunk++)
    blosc2_schunk_decompress_chunk(obj_0, nchunk, (void *) data_dest, isize);

  _garbages->items[_garbages->size]=data_dest;
  _garbages->size++;

  return 0;
}

// blosc2_schunk_to_file(), blosc2_schunk_open()
int api_13 (FuzzedDataProvider& provider) {
  int nchunks = 10;

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t *data_dest = (int32_t*)malloc(isize);
  for (int nchunk = 0; nchunk < nchunks; nchunk++)
    blosc2_schunk_decompress_chunk(obj_0, nchunk, (void *) data_dest, isize);

  _garbages->items[_garbages->size]=data_dest;
  _garbages->size++;

  return 0;
}
