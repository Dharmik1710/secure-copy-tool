#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <gcrypt.h>
#include <stdbool.h>


// Function to check if a file exists
int file_exists(char *filename) {
    return access(filename, F_OK) != -1;
}

/***********************************************************************************
    Parsing command line arguments
************************************************************************************/
void parseArguments(int argc, char* argv[], int* port, bool* lmode, char** lfilename){

    if(argc < 2){
        printf("Usage: %s purdec [-l <input file>] <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            *lfilename = argv[i + 1];
            *lmode = true;
            // if(file_exists(*lfilename) != 0){
            //     perror("file already exist");
            //     exit(EXIT_FAILURE);
            // }
            // Skip the next argument
            i++; 
        } else {
            *port = atoi(argv[i]);
        }
    }

}


// Function to create a TCP server socket
int create_server_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, 5) == -1) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/***********************************************************************************
    get the passphrase from user
************************************************************************************/
void setPassphrase(char *passphrase, size_t max_length){
    int count = 0;
    while(count < 3){
        printf("Password: ");
        if (fgets(passphrase, max_length, stdin)) {
            // Remove trailing newline if present
            passphrase[strcspn(passphrase, "\n")] = '\0';

            if (strlen(passphrase) > 0) {
                return;
            }
        }
        printf("Password is required, max password length is 40, retry!\n");
        count++;
    }
    printf("Failed to get a valid password. Exiting.\n");
    exit(EXIT_FAILURE);
}

/***********************************************************************************
    listen to tcp connection
************************************************************************************/
// Function to accept an incoming connection
int accept_connection(int server_socket) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_socket == -1) {
        perror("accept");
        close(server_socket);
        return -1;
    }

    return client_socket;
}
// Function to receive data from a TCP connection
int recv_data_over_tcp_buffer(int sockfd, char *message, size_t msg_len) {
    int bytes_recv = recv(sockfd, message, msg_len, 0);
    if (bytes_recv == -1) {
        perror("Receiving failed(char* type)");
        close(sockfd);
        return -1;
    }
    return bytes_recv;
}
int recv_data_over_tcp_int(int sockfd, int* message){
    int bytes_recv = recv(sockfd, message, sizeof(int), 0);
    if (bytes_recv == -1) {
        perror("Receiving failed(int type)");
        close(sockfd);
        return -1;
    }
    return bytes_recv;

}
int recv_data_over_tcp_char(int sockfd, char* message){
    int bytes_recv = recv(sockfd, message, sizeof(char), 0);
    if (bytes_recv == -1) {
        perror("Receiving failed(char type)");
        close(sockfd);
        return -1;
    }
    return bytes_recv;
}



/***********************************************************************************
    Debugging tools
************************************************************************************/
void print_buffer(char* buffer, size_t buffer_size) {
    for (size_t i = 0; i < buffer_size; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}
void print_n_chars(const char* str, int n) {
    // Iterate through the string until either n characters are printed or we reach the end of the string
    for (int i = 0; i < n; i++) {
        putchar(str[i]); // Print the character
    }
    putchar('\n'); // Print a newline after printing the characters
}

/***********************************************************************************
    unpad
************************************************************************************/
size_t unpad(char* outbuffer, size_t outbuffersize){
    // printf("padded output :\n");
    // print_buffer(*outbuffer, *outbuffersize);
    
    char lastchar = outbuffer[--outbuffersize];
    int count = 1;
    while(outbuffer[--outbuffersize] == lastchar){
        count++;
    }
    outbuffersize++;
    if(count != (int) lastchar){
        fprintf (stderr, "Error unpad: Invalid padding\n");
        exit(EXIT_FAILURE);        
    }

    return outbuffersize;
}


/***********************************************************************************
    set file name
************************************************************************************/
void strip_last_pur(char *str) {
    // Find the last occurrence of ".pur" in the string
    char *last_pur = strrchr(str, '.');
    if (last_pur != NULL && strcmp(last_pur, ".pur") == 0) {
        // Replace the last occurrence of ".pur" with '\0' to truncate the string
        *last_pur = '\0';
    }
}
void setfilename(int sockfd, char **filename, bool lmode, char* lfilename){
    char received_char;
    int filenamesize;

    if(lmode){
        *filename = malloc(strlen(lfilename) -4);
        memcpy(*filename, lfilename, strlen(lfilename));
    } else{
        recv_data_over_tcp_char(sockfd, &received_char);
        // printf("revieved file name length char: %02X\n", received_char);
        filenamesize = (int)received_char;

        *filename = malloc(filenamesize + 1);
        recv_data_over_tcp_buffer(sockfd, *filename, filenamesize);
        // null terminate filename
        filename[filenamesize] = "\0";
    }


    strip_last_pur(*filename);

    if(file_exists(*filename) != 0){
        perror("file already exist\n");
        exit(-1);
    }

    printf("recieved file name: %s\n", *filename);
}
size_t add_data_to_file(FILE* file, char* outbuffer, int outbuffersize){

    // unpad data
    size_t len2cpy = unpad(outbuffer, outbuffersize);

    // Write a specific number of bytes from the buffer to the file
    if (fwrite(outbuffer, 1, len2cpy, file) != len2cpy) {
        perror("Error writing to file");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    return len2cpy;
}
size_t read_n_bytes_from_file(FILE* file, char* inpbuffer, int num_bytes_to_read) {
    size_t bytes_read = fread(inpbuffer, 1, num_bytes_to_read, file);
    if (bytes_read == 0 && !feof(file)) {
        perror("Error reading from file");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    return bytes_read;
}

size_t read_int_from_file(FILE * file, int* num){
    if (fscanf(file, "%d", num) != 1) {
        perror("Error reading int from file");
        exit(EXIT_FAILURE);   
    }
    fseek(file, 1, SEEK_CUR);
    return sizeof(int);
}


/***********************************************************************************
    Key derivation
************************************************************************************/
void deriveKey(char *passphrase, size_t keysize, char * salt, size_t saltsize, void *keybuffer){

    // variable declarations
    int algo = GCRY_KDF_PBKDF2;
    int subalgo = GCRY_CIPHER_AES256;
    // 8 bytes(64 bits) is bare minimum, 32 bytes(256 bits) is recommended 
    // char *salt = "CS528";
    unsigned long iterations = 5;
    gpg_error_t keyerror;

    /**
     * 
     * key derivation function 
     * 
     * Usage: 
     * gpg_error_t gcry_kdf_derive ( const void *passphrase, size t passphraselen, int algo, int subalgo, const void *salt, size t saltlen, unsigned long iterations, size t keysize, void *keybuffer )
     * 
    */


    keyerror = gcry_kdf_derive(passphrase, strlen(passphrase), algo, subalgo, salt, saltsize, iterations, keysize, keybuffer);
    if(keyerror){
        fprintf (stderr, "Error kdf key derive: %s/%s\n", gcry_strsource(keyerror), gcry_strerror(keyerror));
        exit(EXIT_FAILURE);
    }
    // printf("***********************************************************************************************\n");
    // printf("Printing all key params\n");
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("Password: \n");
    // print_buffer(passphrase, sizeof(passphrase));
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("Password size: %zu\n", sizeof(passphrase));
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("algo: %d\n", algo);
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("subalgo: %d\n", subalgo);
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("salt: \n");
    // print_buffer(salt, saltsize);
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("salt size: %zu\n", saltsize);
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("iterations: %lu\n", iterations);
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("key size: %zu\n", keysize);
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("keybuffer: \n");
    // print_buffer(keybuffer, keysize);
    // printf("-------------------------------------------------------------------------------------------\n");
    // printf("***********************************************************************************************\n");


}




/***********************************************************************************
    set salt
************************************************************************************/
void setsalt(int sockfd, char **salt, size_t saltsize, bool lmode, FILE* encfile){
    // char received_char;

    // recv_data_over_tcp_char(sockfd, &received_char);
    // // printf("revieved file name length char: %02X\n", received_char);
    // *saltsize = (size_t)received_char;
    // printf("revieved salt size: %zu\n", *saltsize);

    *salt = malloc(saltsize);
    if(lmode){
        read_n_bytes_from_file(encfile, *salt, saltsize);
    } else{
        recv_data_over_tcp_buffer(sockfd, *salt, saltsize);        
    }
    // null terminate filename
    printf("revieved salt: %zu\n", saltsize);
}

/***********************************************************************************
    HMAC
************************************************************************************/
void set_hmac_context(gcry_mac_hd_t* hd, char* key, size_t keysize, size_t* hmacsize){
    
    gcry_error_t gcryerror;
    int algo = GCRY_MAC_HMAC_SHA3_256;
    int flags = 0;

    // get hmacsize
    *hmacsize = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA3_256);

    /**
     * set hmac context
     * 
     * Usage:
     * gcry_error_t gcry_mac_open (gcry mac hd t *hd, int algo, unsigned int flags, gcry ctx t ctx)
     * 
    **/
    gcryerror = gcry_mac_open(hd, algo, flags, NULL);
    if(gcryerror){
        fprintf (stderr, "Error mac context: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
        exit(EXIT_FAILURE);
    }

    /**
     * set key into context
     * 
     * Usage:
     * gcry_error_t gcry_mac_setkey (gcry mac hd t h, const void *key, size t keylen)
     * 
    **/
    gcryerror = gcry_mac_setkey(*hd, key, keysize);
    if(gcryerror){
        fprintf (stderr, "Error mac key: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
        exit(EXIT_FAILURE);
    }   

}
void verify_hmac(gcry_mac_hd_t hd, char* buffer, size_t buffersize, char* iv, size_t ivsize, char* hmac, size_t hmacsize){

    char* temp = malloc(buffersize + ivsize);
    // char* hmac = malloc(hmacsize);
        
    memcpy(temp, iv, ivsize);
    memcpy(temp, buffer, buffersize);


    // printf("buffersize: %zu\n", buffersize);
    // printf("iv size: %zu\n", ivsize);

    // printf("temp : \n");
    // print_buffer(temp, hmacsize+ivsize);

    // printf("---------------------------------------------\n");

    // printf("expected hmac: \n");
    // print_buffer(expected_hmac, hmacsize);


    gcry_error_t gcryerror;

    /**
     * update hmac
     * 
     * Usage:
     * gcry_error_t gcry_mac_write (gcry mac hd t h, const void *buffer, size t length)
     * 
    **/
    gcryerror = gcry_mac_write(hd, temp, buffersize + ivsize);
    if(gcryerror){
        fprintf (stderr, "Error mac write: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
        exit(EXIT_FAILURE);
    }

    // /**
    //  * get hmac
    //  * 
    //  * Usage:
    //  * gcry_error_t gcry_mac_read (gcry mac hd t h, void *buffer, size t *length)
    //  * 
    // **/
    // gcryerror = gcry_mac_read(hd, hmac, &hmacsize);
    // if(gcryerror){
    //     fprintf (stderr, "Error mac read: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
    //     exit(EXIT_FAILURE);
    // }


    /**
     * verify hmac
     * 
     * gcry_error_t gcry_mac_verify (gcry mac hd t h, void *buffer, size t length)
    **/
    gcryerror = gcry_mac_verify(hd, hmac, hmacsize);
    if(gcryerror){
        fprintf (stderr, "Error mac verify: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
        exit(EXIT_FAILURE);
    }

    // if (memcmp(hmac, expected_hmac, hmacsize) != 0){
    //     fprintf (stderr, "Error mac verify: \n");
    //     exit(EXIT_FAILURE);
    // } 

    // printf("---------------------------------------------\n");

    // printf("calculated hmac: \n");
    // print_buffer(hmac, hmacsize);

    printf("verified mac successfully\n");


    // free(hmac);

    free(temp);
}



/***********************************************************************************
    decryption context
************************************************************************************/
void set_decrypt_context(gcry_cipher_hd_t* hd, char* key, size_t keysize){

    gcry_error_t gcryerror;
    int algo = GCRY_CIPHER_AES256;
    int mode = GCRY_CIPHER_MODE_CBC;
    unsigned int flag = 0;

    /**
     * Creating the context handle
     * 
     * Usage:
     * gcry_error_t gcry_cipher_open(gcry_cipher_hd_t *hd, int algo, int mode, unsigned int flags)
     * 
    **/
    gcryerror = gcry_cipher_open(hd, algo, mode, flag);
    // check for context error
    if(gcryerror){
        fprintf (stderr, "Error context handle: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
        exit(EXIT_FAILURE);
    }

    /**
     * set key into context
     * 
     * Usage:
     * gcry_error_t gcry_cipher_setkey (gcry cipher hd t h, const void [Function] *k, size t l)
     * 
    **/
    gcryerror = gcry_cipher_setkey(*hd, key, keysize);
    if(gcryerror){
        fprintf (stderr, "Error decrypt set key: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
        exit(EXIT_FAILURE);
    }


}



// /***********************************************************************************
//     decrypt data
// ************************************************************************************/
// void decryption(int chunks, char filename, char* key, char* salt){

//     int datasize;
//     size_t hmacsize = 32;
//     size_t ivsize = 16;

//     char* data;
//     char iv[ivsize];
//     char hmac[hmacsize];







//     while(chunks--){
//         // recv data len and data
//         // data = HMAC + iv + enc data
//         recv_data_over_tcp_int(sockfd, &datasize);



//         // verify HMAC



//         // extract and set iv


//         // decrypt




//     }

// }



/***********************************************************************************
    receive data from network
************************************************************************************/
void recv_net_data(char* passphrase, int sockfd, bool lmode, FILE* encfile, char * lfilename){

    // variable declaration
    gcry_error_t gcryerror;
    gcry_cipher_hd_t hd;
    gcry_mac_hd_t machd; 
    
    size_t keysize = 32;
    size_t saltsize = keysize;
    char *keybuffer = malloc(sizeof(char) * keysize);
    char *salt = malloc(sizeof(char) * saltsize);
    size_t ivsize = 16;
    char *iv = malloc(sizeof(char) * ivsize);
    size_t hmacsize = 32;
    char *hmac = malloc(sizeof(char) * hmacsize);
    // bool is_hmac_verified = false;

    char* filename;
    int num_chunks;
    FILE* file;
    int bytes_read;


    // (hmac)32 + (iv)16 + (data)1024 + (padding)16
    size_t inpbuffersize = 1084;
    size_t outbuffersize = 1040;
    char* inpbuffer = malloc(sizeof(char) * inpbuffersize);
    char* outbuffer = malloc(sizeof(char) * outbuffersize);


    // recv file name len and file name(max length 255)
    setfilename(sockfd, &filename, lmode, lfilename);

    // recv salt len and salt
    setsalt(sockfd, &salt, saltsize, lmode, encfile);    
    

    // recv number of chunks(int - 4 bytes)
    if(lmode){
        read_int_from_file(encfile, &num_chunks);
    } else{
        recv_data_over_tcp_int(sockfd, &num_chunks);
    }
    printf("revieved num chunks: %d\n", num_chunks);

    // derive key
    deriveKey(passphrase, keysize, salt, saltsize, keybuffer);

    // set mac context
    set_hmac_context(&machd, keybuffer, keysize, &hmacsize);

    // set decryption context
    set_decrypt_context(&hd, keybuffer, keysize);

    // open the file with filename to write the bytes
    
    file = fopen(filename, "wb");        

    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    while(num_chunks-- > 0){
        // recv the 
        if(lmode){
            read_int_from_file(encfile, (int *)&inpbuffersize);
        } else{
            recv_data_over_tcp_int(sockfd, (int *)&inpbuffersize);    
        }
        
        inpbuffersize = inpbuffersize - hmacsize - ivsize;
        outbuffersize = inpbuffersize;

        if(lmode){
            bytes_read = read_n_bytes_from_file(encfile, hmac, hmacsize);
            bytes_read += read_n_bytes_from_file(encfile, iv, ivsize);
            bytes_read += read_n_bytes_from_file(encfile, inpbuffer, inpbuffersize);
        } else{
            bytes_read = recv_data_over_tcp_buffer(sockfd, hmac, hmacsize);
            bytes_read += recv_data_over_tcp_buffer(sockfd, iv, ivsize);
            bytes_read += recv_data_over_tcp_buffer(sockfd, inpbuffer, inpbuffersize);
        }

        // verify hmac
        verify_hmac(machd, inpbuffer, inpbuffersize, iv, ivsize, hmac, hmacsize);

        // set iv
        gcryerror = gcry_cipher_setiv(hd, iv, ivsize);
        if(gcryerror){
            fprintf (stderr, "Error set iv: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
            exit(EXIT_FAILURE);
        }

        // decrypt data
        gcryerror = gcry_cipher_decrypt(hd, outbuffer, outbuffersize, inpbuffer, inpbuffersize);
        
        if(gcryerror){
         fprintf (stderr, "Error in decryption: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
         // exit(EXIT_FAILURE);
        }

        // wriet to file
        outbuffersize = add_data_to_file(file, outbuffer, outbuffersize);


        // printf("********************************************************\n");
        // printf("Decryption\n");
        // printf("iv : ");
        // print_n_chars(iv, ivsize);
        // printf("key: ");
        // print_n_chars(keybuffer, keysize);
        // printf("********************************************************\n");


        printf("read %zu bytes, wrote %zu bytes\n", inpbuffersize, outbuffersize);


        // printf("-------------------------------------------------------\n");
        // printf("Input buffer: \n");
        // printf("-------------------------------------------------------\n");
        // print_n_chars(inpbuffer, inpbuffersize);
        // printf("-------------------------------------------------------\n");
        // printf("Output buffer: \n");
        // printf("-------------------------------------------------------\n");
        // print_n_chars(outbuffer, outbuffersize);

    }

    fclose(file);


    /**
     * Freeing the hmac context
     * 
     * Usage:
     * void gcry_mac_close (gcry mac hd t h)
     *  
    **/
    gcry_mac_close(machd);
    /**
     * Freeing the encrypt context
     * 
     * Usage:
     * void gcry_cipher_close (gcry cipher hd t h)
     *  
    **/
    gcry_cipher_close(hd);

    // // free 
    // free(salt);
    // free(keybuffer);
    // free(iv);
    // free(hmac);
    // free(inpbuffer);
    // free(outbuffer);

}


// void process_data(){
//     // variable declaration
//     gcry_error_t gcryerror;
//     gcry_cipher_hd_t hd;
//     gcry_mac_hd_t machd; 
    
//     int algo = GCRY_CIPHER_AES256;
//     int mode = GCRY_CIPHER_MODE_CBC;
//     unsigned int flag = 0;
//     size_t keysize = 32;
//     size_t saltsize = keysize;
//     char *keybuffer = malloc(sizeof(char) * keysize);
//     char *salt = malloc(sizeof(char) * saltsize);
//     size_t ivsize = 16;
//     char *iv = malloc(sizeof(char) * ivsize);
//     size_t hmacsize;
//     char *hmac;
    
//     // size_t inpbuffersize = 1024;
//     // size_t outbuffersize = 1040;
//     // char* inpbuffer = malloc(sizeof(char) * inpbuffersize);
//     // char* outbuffer = malloc(sizeof(char) * outbuffersize);

//     // size_t bytes_read;
    
//     // FILE* file;
//     // struct stat st;
//     // stat(filename, &st);
//     // *filesize = st.st_size;
//     // int num_chunks = ceil((double)*filesize/(1024-1));


//     // set mac context
//     set_hmac_context(&machd, keybuffer, size_t keysize, size_t* hmacsize){




//     // set decryption context
//     set_decrypt_context();





// }



int main(int argc, char *argv[]) {


    int client_socket;
    int server_socket;


    // Parse the input file argument
    char* filename = NULL;
    char* encfilename = NULL;
    int port;
    bool lmode = false;
    char* lfilename;
    char passphrase[41];
    char* filebuffer = NULL;
    char buffer[1040];
    int filesize;
    FILE* encfile;


    // parse command line arguments
    parseArguments(argc, argv, &port, &lmode, &lfilename);

    if(!lmode){
        // Create a TCP server socket
        server_socket = create_server_socket(port);
        if (server_socket == -1) {
            exit(EXIT_FAILURE);
        }        
        printf("Server listening on port %d\n", port);
    }

    

    while(1){

        if(lmode){
            encfile = fopen(lfilename, "rb");
        } else{
            // Accept an incoming connection
            client_socket = accept_connection(server_socket);
            if (client_socket == -1) {
                close(server_socket);
                exit(EXIT_FAILURE);
            }

            printf("Client connected\n");

        }


        // get passphrase
        setPassphrase(passphrase, 40);
        recv_net_data(passphrase, client_socket, lmode, encfile, lfilename);


        if (!lmode)
        {
            close(client_socket);
        }

        if(lmode){
            break;
        }

        // printf("Received data from client: %s\n", buffer);


    }

    if (!lmode)
    {
        close(server_socket);
    }
    

    
    return 0;
}

