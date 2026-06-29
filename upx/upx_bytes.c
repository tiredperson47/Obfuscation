#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    const char *input_filename = argv[1];
    const char *output_filename = argv[2];
    
    int input_fd = -1;
    int output_fd = -1;
    unsigned char *file_data = NULL;
    long file_size;
    bool patched = false;

    // read file
    input_fd = openat(AT_FDCWD, input_filename, O_RDONLY, 0);
    if (input_fd == -1) {
        perror("Error opening input file");
        return 1;
    }

    // Get the size of the file
    struct stat st;
    if (fstat(input_fd, &st) == -1) {
        perror("Error getting file size with fstat");
        close(input_fd);
        return 1;
    }
    file_size = st.st_size;


    // Allocate memory
    file_data = (unsigned char *)malloc(file_size);
    if (file_data == NULL) {
        fprintf(stderr, "Error: Could not allocate memory for file.\n");
        close(input_fd);
        return 1;
    }

    // Read the file into the buffer
    if (read(input_fd, file_data, file_size) != file_size) {
        fprintf(stderr, "Error reading file into buffer.\n");
        free(file_data);
        close(input_fd);
        return 1;
    }
    close(input_fd);

    // Find UPX and patch it
    for (long i = 0; i < file_size - 3; ++i) {
        if (file_data[i] == 0x55 &&
            file_data[i+1] == 0x50 &&
            file_data[i+2] == 0x58 &&
            (file_data[i+3] == 0x30 || file_data[i+3] == 0x21))
        {
            file_data[i] = 0x41; // Change 'U' to 'A'
            patched = true;
            break;
        }
    }

    // save to file
    if (patched) {
        output_fd = openat(AT_FDCWD, output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd == -1) {
            perror("Error opening output file");
            free(file_data);
            return 1;
        }

        if (write(output_fd, file_data, file_size) != file_size) {
            fprintf(stderr, "Error writing modified data to file.\n");
            close(output_fd);
            free(file_data);
            return 1;
        }
        close(output_fd);
    } else {
        printf("Your file was not patched (UPX signature not found).\n");
    }

    free(file_data);
    return 0;
}
