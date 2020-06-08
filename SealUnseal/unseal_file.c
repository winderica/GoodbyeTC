#include "common.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx)
{
    int i, nrounds = 5;
    unsigned char key[32], iv[32];
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 32)
    {
        printf("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }
    EVP_CIPHER_CTX_init(e_ctx);
    EVP_DecryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    return 0;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *plaintext = malloc(c_len);

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &c_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext + c_len, &f_len);

    *len = c_len + f_len;
    return plaintext;
}

void usage(char *pch_name)
{
    printf("Usage: %s source destination\n", pch_name);
    printf("eg: %s cipertext_file plaintext_file\n", pch_name);
}

int main(int argc, char **argv)
{

#define BUF_LEN (1024 * 1024)
#define KEY_SIZE 64
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HKEY hSRK, hKey;
    TSS_HPOLICY hPolicy;
    TSS_HTPM hTPM;
    TSS_HENCDATA hEncData;
    TSS_HPCRS hPcrs;
    UINT32 u32PcrValLen, u32EncDataLen;
    BYTE *rgbPcrVal, *rgbEncData;
    BYTE *random;
    FILE *fpIn = NULL, *fpOut = NULL;
    int len, size;
    char *pBufIn = NULL, *pBufOut = NULL;
    unsigned int salt[] = {12345, 54321};
    EVP_CIPHER_CTX en;
    TSS_UUID UUID_K1 = {0, 0, 0, 0, 0, {8, 0, 0, 0, 0, 1}};

    if (argc < 3)
    {
        usage(argv[0]);
        return 0;
    }

    result = connect_load_all(&hContext, &hSRK, &hTPM);
    if (result)
    {
        printf("connect_load_all failed\n");
        return result;
    }

    result = Tspi_Context_CreateObject(hContext,
                                       TSS_OBJECT_TYPE_ENCDATA,
                                       TSS_ENCDATA_SEAL,
                                       &hEncData);
    if (TSS_SUCCESS != result)
    {
        print_error("Tspi_Context_CreateObject", result);
        Tspi_Context_Close(hContext);
        return result;
    }

    result = set_secret(hContext, hEncData, &hPolicy);
    if (TSS_SUCCESS != result)
    {
        print_error("set_secret", result);
        Tspi_Context_Close(hContext);
        return result;
    }

    result = Tspi_Context_LoadKeyByUUID(hContext,
                                        TSS_PS_TYPE_SYSTEM,
                                        UUID_K1,
                                        &hKey);
    if (TSS_SUCCESS != result)
    {
        print_error("Tspi_Context_LoadKeyByUUID", result);
        Tspi_Context_Close(hContext);
        return -1;
    }

    result = set_popup_secret(hContext,
                              hKey,
                              TSS_POLICY_USAGE,
                              "Input K1's Pin\n",
                              0);
    if (TSS_SUCCESS != result)
    {
        print_error("set_popup_secret", result);
        Tspi_Context_Close(hContext);
        return result;
    }

    fpIn = fopen(argv[1], "rb");

    fread(&u32EncDataLen, 1, sizeof(UINT32), fpIn);
    rgbEncData = malloc(u32EncDataLen);
    fread(rgbEncData, 1, u32EncDataLen, fpIn);
    fread(&size, 1, sizeof(UINT32), fpIn);
    pBufIn = malloc(size);
    fread(pBufIn, 1, size, fpIn);

    fclose(fpIn);

    print_hex(pBufIn, len);
    result = Tspi_SetAttribData(hEncData,
                                TSS_TSPATTRIB_ENCDATA_BLOB,
                                TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                                u32EncDataLen,
                                rgbEncData);
    if (TSS_SUCCESS != result)
    {
        print_error("Tspi_SetAttribData", result);
        Tspi_Context_Close(hContext);
        return result;
    }

    UINT32 ulDataUnsealedLen;
    result = Tspi_Data_Unseal(hEncData,
                              hKey,
                              &ulDataUnsealedLen,
                              &random);
    if (TSS_SUCCESS != result)
    {
        print_error("Tspi_Data_Unseal", result);
        Tspi_Context_Close(hContext);
        return result;
    }

    if (aes_init(random, KEY_SIZE, (unsigned char *)&salt, &en))
    {
        printf("aes_init failed\n");
        Tspi_Context_Close(hContext);
        free(pBufIn);
        return -1;
    }

    pBufOut = aes_decrypt(&en, pBufIn, &size);

    fpOut = fopen(argv[2], "wb");

    fwrite(pBufOut, 1, size, fpOut);

    fclose(fpOut);
    free(pBufIn);
    free(pBufOut);

    Tspi_Context_Close(hContext);

    return 0;
}
