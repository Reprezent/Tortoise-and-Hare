#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define DEBUG 0


unsigned char* HASH(const unsigned char* bytes, size_t size)
{
    unsigned char* buf = calloc(1, SHA256_DIGEST_LENGTH);
    SHA256_CTX* digest = malloc(sizeof(SHA256_CTX));
    SHA256_Init(digest);
    SHA256_Update(digest, bytes, size);
    SHA256_Final(buf, digest);

    return buf;
}
    
void TnH(char* IV, unsigned start)
{
    FILE* LOG = fopen("hits_11.log", "w");
    unsigned char* T_buf = calloc(1, SHA256_DIGEST_LENGTH);
    unsigned char* H_buf = calloc(1, SHA256_DIGEST_LENGTH);
    unsigned char* T_buf2 = calloc(1, SHA256_DIGEST_LENGTH);
    unsigned char* H_buf2 = calloc(1, SHA256_DIGEST_LENGTH);
    unsigned char* temp;
    // unsigned char* H_buf2 = calloc(1, SHA256_DIGEST_LENGTH);
    SHA256_CTX* T_digest = malloc(sizeof(SHA256_CTX));
    SHA256_CTX* H_digest = malloc(sizeof(SHA256_CTX));
    


//    while(start <= SHA256_DIGEST_LENGTH)
    {
        SHA256_Init(T_digest);
        SHA256_Update(T_digest, (const unsigned char*)IV, strlen(IV));
        SHA256_Final(T_buf, T_digest);

        SHA256_Init(H_digest);
        SHA256_Update(H_digest, IV, strlen(IV));
        SHA256_Final(H_buf, H_digest);

        SHA256_Init(H_digest);
        SHA256_Update(H_digest, H_buf, start);
        SHA256_Final(H_buf, H_digest);
        while(memcmp(T_buf, H_buf, start) != 0)
        {
            // Tortise
            SHA256_Init(T_digest);
            SHA256_Update(T_digest, T_buf, start);
            SHA256_Final(T_buf, T_digest);

            // Hare
#           if DEBUG
                printf("Before 1st Hash: 0x");
                for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", H_buf[i]);
                printf("\n");
#           endif

            SHA256_Init(H_digest);
            SHA256_Update(H_digest, H_buf, start);
            SHA256_Final(H_buf, H_digest);

#           if DEBUG
                printf("After  1st Hash: 0x");
                for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", H_buf[i]);
                printf("\n");
#           endif

          //  printf("Before 2nd Hash: 0x");
        //    for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", H_prev[i]);

            SHA256_Init(H_digest);
            SHA256_Update(H_digest, H_buf, start);
            SHA256_Final(H_buf, H_digest);

#           if DEBUG
                printf("After  2nd Hash: 0x");
                for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", H_buf[i]);
                printf("\n"); printf("\n");
#           endif

        }


        SHA256_Init(H_digest);
        SHA256_Update(H_digest, IV, strlen(IV));
        SHA256_Final(H_buf, H_digest);

        while(memcmp(T_buf, H_buf, start) != 0)
        {
            temp = T_buf2;
            T_buf2 = T_buf;
            T_buf = temp;
            SHA256_Init(T_digest);
            SHA256_Update(T_digest, T_buf2, start);
            SHA256_Final(T_buf, T_digest);

#           if DEBUG
                printf("Before 1st Hash: 0x");
                for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", T_buf[i]);
                printf("\n");
#           endif

            temp = H_buf2;
            H_buf2 = H_buf;
            H_buf = temp;
            SHA256_Init(H_digest);
            SHA256_Update(H_digest, H_buf, start);
            SHA256_Final(H_buf, H_digest);

#           if DEBUG
                printf("After  1st Hash: 0x");
                for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", H_buf[i]);
                printf("\n");
#           endif
        }

        printf("Collision Found with N %4u bits.\n", start * 8);
        printf("First  Collision: 0x");
        for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", T_buf2[i]);
        printf("\n");

        printf("Second Collision: 0x");
        for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", H_buf2[i]);
        printf("\n");

        printf("Collision Hash:   0x");
        for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02hhX", H_buf[i]);
        printf("\n");
        
        // ========= LOGGING ========
        fprintf(LOG, "Collision Found with N %4u bits.\n", start * 8);
        fprintf(LOG, "First  Collision: 0x");
        for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) fprintf(LOG, "%02hhX", T_buf2[i]);
        fprintf(LOG, "\n");

        fprintf(LOG, "Second Collision: 0x");
        for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) fprintf(LOG, "%02hhX", H_buf2[i]);
        fprintf(LOG, "\n");

        fprintf(LOG, "Collision Hash:   0x");
        for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) fprintf(LOG, "%02hhX", H_buf[i]);
        fprintf(LOG, "\n");

        fclose(LOG);

    }
}

int main(int argc, char** argv)
{
    TnH("RiedelHouston", 11);
    return 0;
}
