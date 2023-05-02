/*
 *  COMPILING INSTRUCTIONS
 *
 *  Run this with the following clang argument
 *
 *  clang -g -O1 -fsanitize=fuzzer -std=c17 ./target.c -lpgagroal -o ./pgagroal-fuzzer
 *
 * And then run ./pgagroal-fuzzer
 *
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>

#include "../src/include/configuration.h"
#include "../src/include/shmem.h"
#include "../src/include/pgagroal.h"

/*
 * Points to the location where we write output to
 *  This is in the same directory to prevent pollution
 *  of directories
 */
static char *file_name = "./pgagoral-fuzzer.conf";

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    FILE *out_file = NULL;
    size_t shmem_size = 0;
    int ret;
    size_t out_bytes;
    char message[MISC_LENGTH]; // a generic message used for errors
    struct configuration *config = NULL;

    out_file = fopen(file_name, "wb");

    if (out_file == NULL) {
        printf("Error opening file");
        ret = -1;
        goto clean;
    }

     out_bytes = fwrite(data, sizeof(char), size, out_file);
     if (out_bytes != size){
         printf("Error writing to output\n ");
         ret = -1;
         goto clean;
     }
    fflush(out_file);


    // initialize shared memory
    shmem_size = sizeof(struct configuration);

    if (pgagroal_create_shared_memory(shmem_size, HUGEPAGE_OFF, &shmem)) {
        printf("Error in creating shared memory");
        ret = -1;
        goto clean;
    }

    pgagroal_init_configuration(shmem);
    config = (struct configuration *) shmem;

    if ((ret = pgagroal_read_configuration(shmem, file_name, true)) != PGAGROAL_CONFIGURATION_STATUS_OK) {
       //  the configuration has some problem, build up a descriptive message
        if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_NOT_FOUND) {
            snprintf(message, MISC_LENGTH, "Configuration file not found");
        } else if (ret == PGAGROAL_CONFIGURATION_STATUS_FILE_TOO_BIG) {
            snprintf(message, MISC_LENGTH, "Too many sections");
        } else if (ret == PGAGROAL_CONFIGURATION_STATUS_KO) {
            snprintf(message, MISC_LENGTH, "Invalid configuration file");
        } else if (ret > 0) {
            snprintf(message, MISC_LENGTH, "%d problematic or duplicated section%c",
                     ret,
                     ret > 1 ? 's' : ' ');
        }
    }

clean:
    if (out_file != NULL) {
        fclose(out_file);
    }
    if (shmem != NULL) {
        pgagroal_destroy_shared_memory(shmem, shmem_size);
    }

    return ret;

}