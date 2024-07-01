#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <gcrypt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <math.h>


#define extension ".pur"


/***********************************************************************************
    Parsing command line arguments
************************************************************************************/
void parseArguments(int argc, char* argv[], char** inputFile, char** destAddr, int* port, bool* local, char** encfilename){
	
	struct stat filestat;

	if(argc < 2){
		printf("Usage: %s <input file> [-d <output IP-addr:port>] [-l]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            *destAddr = argv[i + 1];
            // Use strtok to tokenize the string by ":"
			char *token = strtok(*destAddr, ":");
            if (token != NULL) {
                *destAddr = token; // Store IP address
                token = strtok(NULL, ":");
                if (token != NULL) {
                    *port = atoi(token); // Store port
                } else {
		            fprintf(stderr, "Invalid destination address format: %s, expected format: purenc <input file> [-d <output IP-addr:port>] [-l]\n", argv[i + 1]);
		            exit(EXIT_FAILURE);
                }
            } else {
                fprintf(stderr, "Invalid destination address format: %s, expected format: purenc <input file> [-d <output IP-addr:port>] [-l]\n", argv[i + 1]);
                exit(EXIT_FAILURE);
            }
            // Skip the next argument
            i++; 
        } else if (strcmp(argv[i], "-l") == 0) {
            *local = true;
        } else {
            *inputFile = argv[i];
            *encfilename = malloc(strlen(argv[1]) + 5);
			if (*encfilename == NULL) {
		        fprintf(stderr, "Memory allocation failed\n");
		        exit(EXIT_FAILURE);
		    }
			strcpy(*encfilename, argv[i]); // Copy the original filename to encfilename
			strcat(*encfilename, ".pur");
        }
    }


    // check if file already exists
    // if(local && stat(*encfilename, &filestat) != 0){
    // 	fprintf (stderr, "Error: %s\n", "File already exist");
    // 	exit(EXIT_FAILURE);
    // }

    // if (inputFile)
    //     printf("Input file: %s\n", inputFile);
    // if (destAddr)
    //     printf("Output address: %s\n", destAddr);
    // if (listen)
    //     printf("Listen mode enabled\n");

}

// Function to check if a file exists
int file_exists(const char *filename) {
    return access(filename, F_OK) != -1;
}

/***********************************************************************************
    read contents of the file
************************************************************************************/
size_t add_data_to_file(FILE* file, char* outbuffer, int outbuffersize){

    // Write a specific number of bytes from the buffer to the file
    size_t bytes_read = fwrite(outbuffer, 1, outbuffersize, file);
    if (bytes_read == 0 && !feof(file)) {
        perror("Error writing to file");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    return outbuffersize;
}
size_t add_data_to_file_int(FILE* file, int num){
	fprintf(file, "%d\n", num);
	// fseek(file, 1, SEEK_CUR);
	return sizeof(int);
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


	// get random salt into salt buffer
	gcry_randomize(salt, saltsize, GCRY_STRONG_RANDOM);

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
    printf("***********************************************************************************************\n");
    printf("Printing all key params\n");
    printf("-------------------------------------------------------------------------------------------\n");
    printf("Password: \n");
    print_buffer(passphrase, sizeof(passphrase));
    printf("-------------------------------------------------------------------------------------------\n");
    printf("Password size: %zu\n", strlen(passphrase));
    printf("-------------------------------------------------------------------------------------------\n");
    printf("algo: %d\n", algo);
    printf("-------------------------------------------------------------------------------------------\n");
    printf("subalgo: %d\n", subalgo);
    printf("-------------------------------------------------------------------------------------------\n");
    printf("salt: \n");
    print_buffer(salt, saltsize);
    printf("-------------------------------------------------------------------------------------------\n");
    printf("salt size: %zu\n", saltsize);
    printf("-------------------------------------------------------------------------------------------\n");
    printf("iterations: %lu\n", iterations);
    printf("-------------------------------------------------------------------------------------------\n");
    printf("key size: %zu\n", keysize);
    printf("-------------------------------------------------------------------------------------------\n");
    printf("keybuffer: \n");
    print_buffer(keybuffer, keysize);
    printf("-------------------------------------------------------------------------------------------\n");
    printf("***********************************************************************************************\n");

	return;
}


/***********************************************************************************
    padding
************************************************************************************/
void pad(char **buffer, size_t *buffer_size, size_t block_size) {
    // Calculate the number of bytes to pad
    size_t padding_length = block_size - (*buffer_size % block_size);

    printf("padding length: %zu\n", padding_length);
    printf("buffer size: %zu\n", *buffer_size);
    
    // Allocate memory for the padded buffer
    char *padded_buffer = (char *)malloc(*buffer_size + padding_length);
    if (padded_buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    // Copy the original buffer to the padded buffer
    memcpy(padded_buffer, *buffer, *buffer_size);
    
    // Add padding bytes
    for (size_t i = *buffer_size; i < *buffer_size + padding_length; i++) {
        padded_buffer[i] = (unsigned char)padding_length;
    }
    
    // Update the buffer and buffer size
    // free(*buffer);
    *buffer = padded_buffer;
    *buffer_size += padding_length;
}

/***********************************************************************************
    create TCP connection
************************************************************************************/
// Function to establish a TCP connection
int tcp_connect(const char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        close(sockfd);
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
}
// Function to send data over a TCP connection
int send_data_over_tcp_buffer(int sockfd, char *message, size_t msg_len) {
    int bytes_sent = send(sockfd, message, msg_len, 0);
    if (bytes_sent == -1) {
        perror("Sending failed(char* type)");
        close(sockfd);
        return -1;
    }
    return bytes_sent;
}
int send_data_over_tcp_int(int sockfd, int message){
	int bytes_sent = send(sockfd, &message, sizeof(int), 0);
    if (bytes_sent == -1) {
        perror("Sending failed(int type)");
        close(sockfd);
        return -1;
    }
    return bytes_sent;
}
int send_data_over_tcp_char(int sockfd, char message){
	int bytes_sent = send(sockfd, &message, sizeof(char), 0);
    if (bytes_sent == -1) {
        perror("Sending failed(char type)");
        close(sockfd);
        return -1;
    }
    return bytes_sent;

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

    printf("Key buffer: \n");
    print_buffer(key, keysize);

	gcryerror = gcry_mac_setkey(*hd, key, keysize);
	if(gcryerror){
		fprintf (stderr, "Error mac key: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		exit(EXIT_FAILURE);
	}	

}
void compute_hmac(gcry_mac_hd_t hd, char* buffer, size_t buffersize, char* iv, size_t ivsize, char** hmac, size_t hmacsize){

	*hmac = malloc(hmacsize);
	char* temp = malloc(buffersize + ivsize);
	
	memcpy(temp, iv, ivsize);	
	memcpy(temp, buffer, buffersize);

    printf("buffersize: %zu\n", buffersize);
    printf("iv size: %zu\n", ivsize);

    printf("temp : \n");
    print_buffer(temp, hmacsize+ivsize);



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

	/**
	 * get hmac
	 * 
	 * Usage:
	 * gcry_error_t gcry_mac_read (gcry mac hd t h, void *buffer, size t *length)
	 * 
	**/
	gcryerror = gcry_mac_read(hd, *hmac, &hmacsize);
	if(gcryerror){
		fprintf (stderr, "Error mac read: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		exit(EXIT_FAILURE);
	}
	printf("---------------------------------------------\n");

    printf("hmac: \n");
    print_buffer(*hmac, hmacsize);

	free(temp);
}



/***********************************************************************************
    Encryption
************************************************************************************/
void my_encrypt(char *passphrase, char * filename, size_t* filesize, int sockfd, bool lmode, FILE * outfile){

	// variable declaration
	gcry_error_t gcryerror;
	gcry_cipher_hd_t hd;
	gcry_mac_hd_t machd; 
	
	int algo = GCRY_CIPHER_AES256;
	int mode = GCRY_CIPHER_MODE_CBC;
	unsigned int flag = 0;
	size_t keysize = 32;
	size_t saltsize = keysize;
	char *keybuffer = malloc(sizeof(char) * keysize);
	char *salt = malloc(sizeof(char) * saltsize);
	size_t ivsize = 16;
	char *iv = malloc(sizeof(char) * ivsize);
	size_t hmacsize = 32;
	char *hmac;
	
	size_t inpbuffersize = 1040;
	size_t outbuffersize = 1084;
	char* inpbuffer = malloc(sizeof(char) * inpbuffersize);
	char* outbuffer = malloc(sizeof(char) * outbuffersize);

	size_t bytes_read;
    
    FILE* file;
    struct stat st;
    stat(filename, &st);
    *filesize = st.st_size;
    int num_chunks = ceil((double)*filesize/(1024));

    int bytes_sent = 0;



	/**
	 * Creating the context handle
	 * 
	 * Usage:
	 * gcry_error_t gcry_cipher_open(gcry_cipher_hd_t *hd, int algo, int mode, unsigned int flags)
	 * 
	**/
	gcryerror = gcry_cipher_open(&hd, algo, mode, flag);
	// check for context error
	if(gcryerror){
		fprintf (stderr, "Error context handle: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		exit(EXIT_FAILURE);
	}




	/**
	 * set key context
	 * 
	 * Usage:
	 * gcry_error_t gcry_cipher_setkey (gcry cipher hd t h, const void [Function] *k, size t l)
	 * 
	**/
	deriveKey(passphrase, keysize, salt, saltsize, keybuffer);
	// send salt
	// send_data_over_tcp_char(sockfd, (char)saltsize);
	if(lmode){
		printf("before salt\n");
		add_data_to_file(outfile, salt, saltsize);
		printf("after salt\n");
	} else{
		send_data_over_tcp_buffer(sockfd, salt, saltsize);		
	}


	// printf("deriving key: %s\n", "no error");

	gcryerror = gcry_cipher_setkey(hd, keybuffer, keysize);
	if(gcryerror){
		fprintf (stderr, "Error set key: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		exit(EXIT_FAILURE);
	}

	/**
	 * initialize hmac
	 * 
	**/
	set_hmac_context(&machd, keybuffer, keysize, &hmacsize);



	file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", filename);
        exit(EXIT_FAILURE);
    }
    printf("file size: %zu\n", *filesize);
    printf("chunks: %d\n", num_chunks);

    // number of chunks
    if(lmode){
		add_data_to_file_int(outfile, num_chunks);
    } else {
    	send_data_over_tcp_int(sockfd, num_chunks);
    }
	while ((bytes_read = fread(inpbuffer, 1, 1024, file)) > 0) {

		// padding
		inpbuffersize = bytes_read;
		pad(&inpbuffer, &inpbuffersize, 16);
		outbuffersize = inpbuffersize;

		/**
		 * set iv
		 * 
		 * Usage:
		 * gcry_error_t gcry_cipher_setiv (gcry cipher hd t h, const void *k, size t l)
		 * 
		**/
		gcry_randomize(iv, ivsize, GCRY_STRONG_RANDOM);
		gcryerror = gcry_cipher_setiv(hd, iv, ivsize);
		if(gcryerror){
			fprintf (stderr, "Error set iv: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
			exit(EXIT_FAILURE);
		}


		gcryerror = gcry_cipher_encrypt(hd, outbuffer, outbuffersize, inpbuffer, inpbuffersize);
		if(gcryerror){
			fprintf (stderr, "Error in encryption: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
			exit(EXIT_FAILURE);
		}

		
		// printf("-------------------------------------------------------\n");
		// printf("Output buffer before hmac: \n");
		// print_n_chars(outbuffer, outbuffersize);
		// printf("Output buffer size before hmac: %zu\n", outbuffersize);
		// printf("-------------------------------------------------------\n");


		/**
		 * compute hmac
		 * 
		**/
		compute_hmac(machd, outbuffer, outbuffersize, iv, ivsize, &hmac, hmacsize);
		
		printf("hmac: \n");
		print_n_chars(hmac, hmacsize);
	    printf("-------------------------------------------------------------------------------------------\n");
	    printf("hmac size: %zu\n", hmacsize);
	    printf("-------------------------------------------------------------------------------------------\n");

		// printf("hmacsize: %zu\n", hmacsize);

		// /**
		//  * verify hmac
		//  * 
		//  * gcry_error_t gcry_mac_verify (gcry mac hd t h, void *buffer, size t length)
		// **/
		// char* temp = malloc(hmacsize);
		// memcpy(temp, outbuffer, hmacsize);
		// gcryerror = gcry_mac_verify(machd, temp, hmacsize);
		// if(gcryerror){
		// 	fprintf (stderr, "Error mac verify: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		// 	exit(EXIT_FAILURE);
		// }




		// printf("********************************************************\n");
		// printf("Ecryption\n");
		// printf("iv : ");
		// print_n_chars(iv, 16);
		// printf("key: ");
		// print_n_chars(keybuffer, keysize);
		// printf("********************************************************\n");

		if(lmode){
			add_data_to_file_int(outfile, outbuffersize + ivsize + hmacsize);
			bytes_sent = add_data_to_file(outfile, hmac, hmacsize);
			bytes_sent += add_data_to_file(outfile, iv, ivsize);
			bytes_sent += add_data_to_file(outfile, outbuffer, outbuffersize);
		} else{		
			send_data_over_tcp_int(sockfd, outbuffersize + ivsize + hmacsize);
			bytes_sent = send_data_over_tcp_buffer(sockfd, hmac, hmacsize);
			bytes_sent += send_data_over_tcp_buffer(sockfd, iv, ivsize);
			bytes_sent += send_data_over_tcp_buffer(sockfd, outbuffer, outbuffersize);
		}

		printf("read %zu bytes, wrote %d bytes(hmac = %zu,iv = %zu, data = %zu)\n", bytes_read, bytes_sent, hmacsize, ivsize, outbuffersize);


		// printf("-------------------------------------------------------\n");
		// printf("Input buffer: \n");
		// printf("-------------------------------------------------------\n");
		// print_n_chars(inpebuffer, inpbuffersize);
		// printf("-------------------------------------------------------\n");
		// printf("Output buffer: \n");
		// printf("-------------------------------------------------------\n");
		// print_n_chars(outebuffer, outbuffersize);
		
		// printf("********************************************************\n");
		// printf("Decryption\n");
		// printf("iv : ");
		// print_n_chars(iv, 16);
		// printf("key: ");
		// print_n_chars(keybuffer, keysize);

		// printf("********************************************************\n");

		// gcryerror = gcry_cipher_reset(hd);
		// if(gcryerror){
		// 	fprintf (stderr, "Error in decryption: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		// 	// exit(EXIT_FAILURE);
		// }

		// gcryerror = gcry_cipher_setkey(hd, keybuffer, keysize);
		// if(gcryerror){
		// 	fprintf (stderr, "Error set key: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		// 	exit(EXIT_FAILURE);
		// }

		// gcryerror = gcry_cipher_setiv(hd, iv, ivsize);
		// if(gcryerror){
		// 	fprintf (stderr, "Error set iv: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		// 	exit(EXIT_FAILURE);
		// }


		// gcryerror = gcry_cipher_decrypt(hd, outdbuffer, inpbuffersize, outebuffer, outbuffersize);
		// if(gcryerror){
		// 	fprintf (stderr, "Error in decryption: %s/%s\n", gcry_strsource(gcryerror), gcry_strerror(gcryerror));
		// 	// exit(EXIT_FAILURE);
		// }
		// printf("read %zu bytes, wrote %zu bytes\n", outbuffersize, inpbuffersize);
		// printf("-------------------------------------------------------\n");
		// printf("Input buffer: \n");
		// printf("-------------------------------------------------------\n");
		// print_n_chars(outebuffer, outbuffersize);
		// printf("-------------------------------------------------------\n");
		// printf("Output buffer: \n");
		// printf("-------------------------------------------------------\n");
		// print_n_chars(outdbuffer, inpbuffersize);

	}
	
	// gcryerror = gcry_cipher_encrypt(hd, unsigned char *out, size t outsize, const unsigned char *in, size t inlen)



    // if (salt)
    //     printf("salt: %s\n", salt);
    // if (keybuffer)
    //     printf("key: %s\n", keybuffer);
    // if (iv)
    //     printf("iv: %s\n", iv);

    // close the file
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

	// free 
	// free(salt);
	// free(keybuffer);
	// free(iv);
	// free(hmac);
	// free(inpbuffer);
	// free(outbuffer);

}




int main(int argc, char *argv[]) {


    // Parse the input file argument
    char* filename = NULL;
    char* encfilename = NULL;
    char* destAddr = NULL;
    int destport;

    bool lmode = false;
    char passphrase[41];
    char* filebuffer = NULL;
    size_t filesize; 
    FILE *encfile;
    FILE *inpfile;

    int sockfd = 1;

    // parse command line arguments
    parseArguments(argc, argv, &filename, &destAddr, &destport, &lmode, &encfilename);

    // get passphrase
    setPassphrase(passphrase, 40);    
    
    
    if(destAddr){
		// create tcp connection
		sockfd = tcp_connect(destAddr, destport);
		send_data_over_tcp_char(sockfd, (char)strlen(encfilename));
		send_data_over_tcp_buffer(sockfd, encfilename, strlen(encfilename));
    }

    if(lmode){
    	printf("lmode\n");
    	// check if filename already exist
    	if(file_exists(encfilename) != 0){
    		fprintf(stderr, "File already exists");
			exit(EXIT_FAILURE);
    	}
    	encfile = fopen(encfilename, "wb");
    	printf("efilename: %s\n", encfilename);
    }

    // // input file
    // inpfile = fopen(filename, "rb");
    // if (inpfile == NULL) {
    //     fprintf(stderr, "Unable to open file %s\n", filename);
    //     exit(EXIT_FAILURE);
    // }


    // encryption
    my_encrypt(passphrase, filename, &filesize, sockfd, lmode, encfile);

    if(lmode)
    	fclose(encfile);

    printf("Successfully encrypted %s to %s(%zu bytes written)\n", filename, encfilename, filesize);


    return 0;
}
