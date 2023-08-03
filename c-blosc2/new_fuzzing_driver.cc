#include "blosc2.h"

#include <cstdint>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <cstring>

#ifdef DEBUG
# define DEBUG_PRINT(x) printf x; \
        fflush(stdout)
#else
#define DEBUG_PRINT(x) do {} while (0)
#endif

#ifdef DEBUG
#define DEBUG_PRINT_ARRAY(_arr, _size) \
        printf("["); \
        for (int i = 0; i < _size; i++) \
            printf("%d ", _arr[i]); \
        printf("\b]\n")
#else
# define DEBUG_PRINT_ARRAY(_arr, _size) do {} while (0)
#endif

#define MAX_API_SEQ_LEN 13
#define DEFINED_API_BLOCK_N 34
#define BANK_EACH_OBJ_LEN 6

typedef struct garbages {
    void *items[1000];
    int size = 0;
} garbages;

garbages *_garbages;


blosc2_schunk * obj_schunks[BANK_EACH_OBJ_LEN];

int init_0 ();
int init_1 ();
int init_12 ();
int init_19 (FuzzedDataProvider& provider);
int init_20 (FuzzedDataProvider& provider);

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

int api_13 (FuzzedDataProvider& provider);
int api_14 (FuzzedDataProvider& provider);
int api_15 (FuzzedDataProvider& provider);
int api_16 (FuzzedDataProvider& provider);
int api_17 (FuzzedDataProvider& provider);
int api_18 (FuzzedDataProvider& provider);

int api_21 (FuzzedDataProvider& provider);
int api_22 (FuzzedDataProvider& provider);
int api_23 (FuzzedDataProvider& provider);
int api_24 (FuzzedDataProvider& provider);
int api_25 (FuzzedDataProvider& provider);
int api_26 (FuzzedDataProvider& provider);
int api_27 (FuzzedDataProvider& provider);
int api_28 (FuzzedDataProvider& provider);
int api_29 (FuzzedDataProvider& provider);
int api_30 (FuzzedDataProvider& provider);
int api_31 (FuzzedDataProvider& provider);
int api_32 (FuzzedDataProvider& provider);
int api_33 (FuzzedDataProvider& provider);
int api_34 (FuzzedDataProvider& provider);
int api_35 (FuzzedDataProvider& provider);
int api_36 (FuzzedDataProvider& provider);
int api_37 (FuzzedDataProvider& provider);
int api_38 (FuzzedDataProvider& provider);
int api_39 (FuzzedDataProvider& provider);

#define CHUNKSIZE (200 * 1000)
#define NTHREADS (2)

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {

    char **new_argv = (char **)malloc((*argc + 2) * sizeof(char *));
    memcpy(new_argv, *argv, sizeof(*new_argv) * *argc);
    new_argv[*argc] = (char *)"-detect_leaks=0";
    new_argv[*argc + 1] = 0;
    (*argc)++;
    *argv = new_argv;

 return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

  // Initialize global var for global scopes
  {
    _garbages = (garbages*)malloc(sizeof(garbages));
    _garbages->size = 0;

    if (access(".test_file.b2frame", F_OK) == 0) {
        remove(".test_file.b2frame");
    }

    blosc2_init();

    memset(obj_schunks, 0, sizeof(void*) * BANK_EACH_OBJ_LEN);

  }
  FuzzedDataProvider provider(data, size);


  init_0(); // obj_schunks[0] <- (urlpath="dir.b2frame")
  init_1(); // obj_schunks[1] <- (urlpath="dir.b2frame/")
  init_12(); // obj_schunks[2] <- (urlpath="dir1.b2frame")
  init_19(provider); // obj_schunks[3] <- (urlpath="test_sframe.b2frame"), (bool, bool, bool)
  init_20(provider); // obj_schunks[4] <- (urlpath="test_sframe.b2frame/"), (bool, bool, bool)
  obj_schunks[5] = 0x0;

  size_t api_seq_len = (size_t) provider.ConsumeIntegralInRange<uint8_t>(0, MAX_API_SEQ_LEN);
  //size_t api_seq_len = 4;
  DEBUG_PRINT(("DEBUG: API sequence length: %zu \n", api_seq_len));

  for (int i = 0; i < api_seq_len; i++) {

     size_t selected = (size_t) provider.ConsumeIntegralInRange<uint8_t>(0, DEFINED_API_BLOCK_N);
       DEBUG_PRINT(("DEBUG: Selected API index %zu", selected));

     if (selected < 10) {
       DEBUG_PRINT((": call api_%zu() \n", selected+2));
     }
     else if (selected < 16) {
       DEBUG_PRINT((": call api_%zu() \n", selected+3));
     }
     else {
       DEBUG_PRINT((": call api_%zu() \n", selected+5));
     }

     int ret;
     switch (selected) {
// +2
     case 0:
       ret = api_2(provider);
       if (ret == -1) return 0;
       break;

     case 1:
       ret = api_3(provider);
       if (ret == -1) return 0;
       break;

     case 2:
       ret = api_4(provider);
       if (ret == -1) return 0;
       break;

     case 3:
       ret = api_5(provider);
       if (ret == -1) return 0;
       break;

     case 4:
       ret = api_6(provider);
       if (ret == -1) return 0;
       break;

     case 5:
       ret = api_7(provider);
       if (ret == -1) return 0;
       break;

     case 6:
       ret = api_8(provider);
       if (ret == -1) return 0;
       break;

     case 7:
       ret = api_9(provider);
       if (ret == -1) return 0;
       break;

     case 8:
       ret = api_10(provider);
       if (ret == -1) return 0;
       break;

     case 9:
       ret = api_11(provider);
       if (ret == -1) return 0;
       break;

// +1
     case 10:
       ret = api_13(provider);
       if (ret == -1) return 0;
       break;

     case 11:
       ret = api_14(provider);
       if (ret == -1) return 0;
       break;

     case 12:
       ret = api_15(provider);
       if (ret == -1) return 0;
       break;

     case 13:
       ret = api_16(provider);
       if (ret == -1) return 0;
       break;

     case 14:
       ret = api_17(provider);
       if (ret == -1) return 0;
       break;

     case 15:
       ret = api_18(provider);
       if (ret == -1) return 0;
       break;

// +2
     case 16:
       ret = api_21(provider);
       if (ret == -1) return 0;
       break;

     case 17:
       ret = api_22(provider);
       if (ret == -1) return 0;
       break;

     case 18:
       ret = api_23(provider);
       if (ret == -1) return 0;
       break;

     case 19:
       ret = api_24(provider);
       if (ret == -1) return 0;
       break;

     case 20:
       ret = api_25(provider);
       if (ret == -1) return 0;
       break;

     case 21:
       ret = api_26(provider);
       if (ret == -1) return 0;
       break;

     case 22:
       ret = api_27(provider);
       if (ret == -1) return 0;
       break;

     case 23:
       ret = api_28(provider);
       if (ret == -1) return 0;
       break;

     case 24:
       ret = api_29(provider);
       if (ret == -1) return 0;
       break;

     case 25:
       ret = api_30(provider);
       if (ret == -1) return 0;
       break;

     case 26:
       ret = api_31(provider);
       if (ret == -1) return 0;
       break;

     case 27:
       ret = api_32(provider);
       if (ret == -1) return 0;
       break;

     case 28:
       ret = api_33(provider);
       if (ret == -1) return 0;
       break;

     case 29:
       ret = api_34(provider);
       if (ret == -1) return 0;
       break;

     case 30:
       ret = api_35(provider);
       if (ret == -1) return 0;
       break;

     case 31:
       ret = api_36(provider);
       if (ret == -1) return 0;
       break;

     case 32:
       ret = api_37(provider);
       if (ret == -1) return 0;
       break;

     case 33:
       ret = api_38(provider);
       if (ret == -1) return 0;
       break;

     case 34:
       ret = api_39(provider);
       if (ret == -1) return 0;
       break;

     }
  }

// Destruct vars for global scope
  {
    /*
    for (int i = 0; i < BANK_EACH_OBJ_LEN; i++) {
        free(obj_schunks[i]);
    }
    */

    blosc2_destroy();

    for (int i = 0; i < _garbages->size; i++)
        free(_garbages->items[i]);
    free(_garbages);
  }

  return 0;
}
//blosc2_schunk * obj_schunks[BANK_EACH_OBJ_LEN];
int init_0 () {
    char *directory = "dir1.b2frame";
    blosc2_cparams cparams = BLOSC2_CPARAMS_DEFAULTS;
    blosc2_dparams dparams = BLOSC2_DPARAMS_DEFAULTS;            
    cparams.typesize = sizeof(int32_t);
    cparams.clevel = 9;
    cparams.nthreads = NTHREADS;
    dparams.nthreads = NTHREADS;
    blosc2_storage storage = {.contiguous=false, .urlpath=directory, .cparams=&cparams, .dparams=&dparams};
    blosc2_remove_dir(storage.urlpath);

    obj_schunks[0] = blosc2_schunk_new(&storage);

    return 0;
}

int init_1 () {
    char *directory = "dir1.b2frame/";
    blosc2_cparams cparams = BLOSC2_CPARAMS_DEFAULTS;
    blosc2_dparams dparams = BLOSC2_DPARAMS_DEFAULTS;            
    cparams.typesize = sizeof(int32_t);
    cparams.clevel = 9;
    cparams.nthreads = NTHREADS;
    dparams.nthreads = NTHREADS;
    blosc2_storage storage = {.contiguous=false, .urlpath=directory, .cparams=&cparams, .dparams=&dparams};
    blosc2_remove_dir(storage.urlpath);

    obj_schunks[1] = blosc2_schunk_new(&storage);

    return 0;
}

int init_19 (FuzzedDataProvider& provider) {
  //int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_0_idx = 3;
  //DEBUG_PRINT(("INIT(19)  uint8_t: %d\n", obj_0_idx));

  char *directory = "test_sframe.b2frame";
  bool input1 = provider.ConsumeBool();
  bool input2 = provider.ConsumeBool();
  bool input3 = provider.ConsumeBool();

  DEBUG_PRINT(("INIT(19):  (%d, %d, %d)\n", input1, input2, input3));

  blosc2_cparams cparams = BLOSC2_CPARAMS_DEFAULTS;
  blosc2_dparams dparams = BLOSC2_DPARAMS_DEFAULTS;
  if (input1) {
    cparams.filters[BLOSC2_MAX_FILTERS - 2] = BLOSC_DELTA;
    cparams.filters_meta[BLOSC2_MAX_FILTERS - 2] = 0;
  }
  cparams.typesize = sizeof(int32_t);
  if (input2) {
    cparams.compcode = BLOSC_BLOSCLZ;
  } else {
    cparams.compcode = BLOSC_LZ4;
  }
  if (input3) {
    cparams.nthreads = NTHREADS;
    dparams.nthreads = NTHREADS;
  }
  else {
    cparams.nthreads = 1;
    dparams.nthreads = 1;
  }
  blosc2_storage storage = {.contiguous=false, .urlpath=directory, .cparams=&cparams, .dparams=&dparams};

  blosc2_remove_dir(storage.urlpath);
  obj_schunks[obj_0_idx] = blosc2_schunk_new(&storage);

  return 0;
}

int init_20 (FuzzedDataProvider& provider) {
  //int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  int obj_0_idx = 4;
  //DEBUG_PRINT(("INIT(20)  uint8_t: %d\n", obj_0_idx));

  char *directory = "test_sframe.b2frame/";
  bool input1 = provider.ConsumeBool();
  bool input2 = provider.ConsumeBool();
  bool input3 = provider.ConsumeBool();

  DEBUG_PRINT(("INIT(20):  (%d, %d, %d)\n", input1, input2, input3));

  blosc2_cparams cparams = BLOSC2_CPARAMS_DEFAULTS;
  blosc2_dparams dparams = BLOSC2_DPARAMS_DEFAULTS;
  if (input1) {
    cparams.filters[BLOSC2_MAX_FILTERS - 2] = BLOSC_DELTA;
    cparams.filters_meta[BLOSC2_MAX_FILTERS - 2] = 0;
  }
  cparams.typesize = sizeof(int32_t);
  if (input2) {
    cparams.compcode = BLOSC_BLOSCLZ;
  } else {
    cparams.compcode = BLOSC_LZ4;
  }
  if (input3) {
    cparams.nthreads = NTHREADS;
    dparams.nthreads = NTHREADS;
  }
  else {
    cparams.nthreads = 1;
    dparams.nthreads = 1;
  }
  blosc2_storage storage = {.contiguous=false, .urlpath=directory, .cparams=&cparams, .dparams=&dparams};

  blosc2_remove_dir(storage.urlpath);
  obj_schunks[obj_0_idx] = blosc2_schunk_new(&storage);

  return 0;
}

int init_12 () {
  //int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  //DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  int obj_0_idx = 2;

  char *directory = "dir1.b2frame";
  blosc2_cparams cparams = BLOSC2_CPARAMS_DEFAULTS;
  blosc2_dparams dparams = BLOSC2_DPARAMS_DEFAULTS;

  cparams.typesize = 7;
  cparams.clevel = 9;
  cparams.nthreads = NTHREADS;
  dparams.nthreads = NTHREADS;
  blosc2_storage storage = {.contiguous=false, .urlpath=directory, .cparams=&cparams, .dparams=&dparams};
  blosc2_remove_dir(storage.urlpath);
  obj_schunks[obj_0_idx] = blosc2_schunk_new(&storage);

  return 0;
}
//  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
//  DEBUG_PRINT_ARRAY(input_1, input_1_size);

int api_2 (FuzzedDataProvider& provider) {

  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 0;
  int32_t data[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk;
    }
    int64_t _nchunks = blosc2_schunk_append_buffer(obj_0, data, isize);
  }

  return 0;
}


int api_3 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 1;
  int32_t data[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk;
    }
    int64_t _nchunks = blosc2_schunk_append_buffer(obj_0, data, isize);
  }

  return 0;
}

int api_4 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 2;
  int32_t data[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk;
    }
    int64_t _nchunks = blosc2_schunk_append_buffer(obj_0, data, isize);
  }

  return 0;
}

int api_5 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 10;
  int32_t data[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk;
    }
    int64_t _nchunks = blosc2_schunk_append_buffer(obj_0, data, isize);
  }

  return 0;
}

int api_6 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 0;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data_dest[CHUNKSIZE];
  for (int nchunk = nchunks-1; nchunk >= 0; nchunk--) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, data_dest, isize);
  }

  return 0;
}

int api_7 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 1;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data_dest[CHUNKSIZE];
  for (int nchunk = nchunks-1; nchunk >= 0; nchunk--) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, data_dest, isize);
  }

  return 0;
}

int api_8 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 2;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data_dest[CHUNKSIZE];
  for (int nchunk = nchunks-1; nchunk >= 0; nchunk--) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, data_dest, isize);
  }

  return 0;
}


int api_9 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 10;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data_dest[CHUNKSIZE];
  for (int nchunk = nchunks-1; nchunk >= 0; nchunk--) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, data_dest, isize);
  }

  return 0;
}

int api_10 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 10;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data_dest[CHUNKSIZE];
  blosc2_schunk_decompress_chunk(obj_0, 1, data_dest, isize);

  return 0;
}

int api_11 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  blosc2_schunk_free(obj_0);

  return 0;
}


int api_13 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 1;
  int32_t data[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);

  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk;
    }
    blosc2_schunk_append_buffer(obj_0, data, isize);
  }

  return 0;
}

int api_14 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 10;
  int32_t data[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);

  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk;
    }
    blosc2_schunk_append_buffer(obj_0, data, isize);
  }

  return 0;
}

int api_15 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 1;
  int32_t data_dest[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);

  for (int nchunk = nchunks-1; nchunk >= 0; nchunk--) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, data_dest, isize);
  }

  return 0;
}

int api_16 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 10;
  int32_t data_dest[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);

  for (int nchunk = nchunks-1; nchunk >= 0; nchunk--) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, data_dest, isize);
  }

  return 0;
}

int api_17 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int32_t data_dest[CHUNKSIZE];
  int32_t isize = CHUNKSIZE * sizeof(int32_t);

  blosc2_schunk_decompress_chunk(obj_0, 1, data_dest, isize);

  return 0;
}

int api_18 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  blosc2_schunk_free(obj_0);

  return 0;
}


int api_21 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  blosc2_meta_add(obj_0, "metalayer1", (uint8_t *) "my metalayer1", sizeof("my metalayer1"));
  blosc2_meta_add(obj_0, "metalayer2", (uint8_t *) "my metalayer1", sizeof("my metalayer1"));

  return 0;
}

int api_22 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  char* content = "This is a pretty long string with a good number of chars";   
  char* content2 = "This is a pretty long string with a good number of chars; longer than content";

  blosc2_vlmeta_add(obj_0, "vlmetalayer", (uint8_t *) content, (int32_t) strlen(content), NULL);
  blosc2_vlmeta_add(obj_0, "vlmetalayer2", (uint8_t *) content2, (int32_t) strlen(content2), NULL);
 
  return 0;
}

int api_23 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  char *directory = "test_sframe.b2frame";

  blosc2_schunk_free(obj_0);
  obj_schunks[obj_0_idx] = blosc2_schunk_open(directory);
 
  return 0;
}

int api_24 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  char *directory = "test_sframe.b2frame/";

  blosc2_schunk_free(obj_0);
  obj_schunks[obj_0_idx] = blosc2_schunk_open(directory);
 
  return 0;
}

int api_25 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  uint8_t* _content;
  int32_t _content_len;
  blosc2_meta_get(obj_0, "metalayer1", &_content, &_content_len);
  if (_content != NULL) {
    free(_content);
  }
  blosc2_meta_get(obj_0, "metalayer2", &_content, &_content_len);
  if (_content != NULL) {
    free(_content);
  }
 
  return 0;
}

int api_26 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];


  uint8_t* content_;
  int32_t content_len_;
  blosc2_vlmeta_get(obj_0, "vlmetalayer", &content_, &content_len_);
  char* content2 = "This is a pretty long string with a good number of chars; longer than content";

  free(content_);
  blosc2_vlmeta_update(obj_0, "vlmetalayer", (uint8_t *) content2, (int32_t) strlen(content2), NULL);
 
  return 0;
}

int api_27 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 1;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data[CHUNKSIZE];
  int64_t _nchunks = 0;
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk * CHUNKSIZE;
    }
    _nchunks = blosc2_schunk_append_buffer(obj_0, data, isize);
  }
 
  return 0;
}

int api_28 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 2;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data[CHUNKSIZE];
  int64_t _nchunks = 0;
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk * CHUNKSIZE;
    }
    _nchunks = blosc2_schunk_append_buffer(obj_0, data, isize);
  }
 
  return 0;
}

int api_29 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 10;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data[CHUNKSIZE];
  int64_t _nchunks = 0;
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    for (int i = 0; i < CHUNKSIZE; i++) {
      data[i] = i + nchunk * CHUNKSIZE;
    }
    _nchunks = blosc2_schunk_append_buffer(obj_0, data, isize);
  }
 
  return 0;
}

int api_30 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  uint8_t* _content;
  int32_t _content_len;
  blosc2_meta_get(obj_0, "metalayer1", &_content, &_content_len);
  if (_content != NULL) {
    free(_content);
  }
  blosc2_meta_get(obj_0, "metalayer2", &_content, &_content_len);
  if (_content != NULL) {
    free(_content);
  }
  blosc2_meta_update(obj_0, "metalayer2", (uint8_t *) "my metalayer2", sizeof("my metalayer2")); 

  return 0;
}

int api_31 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  uint8_t* content_;
  int32_t content_len_;
  char* content3 = "This is a short string, and shorter than content";
  size_t content_len3 = strlen(content3);
  blosc2_vlmeta_get(obj_0, "vlmetalayer", &content_, &content_len_);
  free(content_);
  blosc2_vlmeta_update(obj_0, "vlmetalayer", (uint8_t *) content3, (int32_t) content_len3, NULL);

  return 0;
}

int api_32 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  char *directory = "test_sframe.b2frame";
  blosc2_schunk_free(obj_0);
  obj_schunks[obj_0_idx] = blosc2_schunk_open(directory);

  return 0;
}

int api_33 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  char *directory = "test_sframe.b2frame/";
  blosc2_schunk_free(obj_0);
  obj_schunks[obj_0_idx] = blosc2_schunk_open(directory);

  return 0;
}

int api_34 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 1;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data_dest[CHUNKSIZE];
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, (void *) data_dest, isize);
  }

  return 0;
}

int api_35 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 2;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data_dest[CHUNKSIZE];
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, (void *) data_dest, isize);
  }

  return 0;
}

int api_36 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  int nchunks = 10;
  int32_t isize = CHUNKSIZE * sizeof(int32_t);
  int32_t data_dest[CHUNKSIZE];
  for (int nchunk = 0; nchunk < nchunks; nchunk++) {
    blosc2_schunk_decompress_chunk(obj_0, nchunk, (void *) data_dest, isize);
  }

  return 0;
}

int api_37 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  uint8_t* _content;
  int32_t _content_len;
  blosc2_meta_get(obj_0, "metalayer1", &_content, &_content_len);
  if (_content != NULL) {
    free(_content);
  }
  blosc2_meta_get(obj_0, "metalayer2", &_content, &_content_len);
  if (_content != NULL) {
    free(_content);
  }

  return 0;
}

int api_38 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  uint8_t* content_;
  int32_t content_len_;
  blosc2_vlmeta_get(obj_0, "vlmetalayer", &content_, &content_len_);
  free(content_);

  return 0;
}

int api_39 (FuzzedDataProvider& provider) {
  int obj_0_idx = (int) provider.ConsumeIntegralInRange<uint8_t>(0, BANK_EACH_OBJ_LEN);
  DEBUG_PRINT(("uint8_t: %d\n", obj_0_idx));
  blosc2_schunk *obj_0 = obj_schunks[obj_0_idx];

  blosc2_schunk_free(obj_0);

  return 0;
}
