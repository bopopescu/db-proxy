#include <string.h>
#include <openssl/evp.h>

const int LEN = 1024;

int main(int argc, char** argv)
{
    EVP_CIPHER_CTX ctx; 
    const EVP_CIPHER* cipher = EVP_rc4();
    unsigned char key[] = "590b6dee278c9d";

    int i;
    for (i = 1; i < argc; ++i) {
        //1. DES����
        EVP_CIPHER_CTX_init(&ctx);
        if (EVP_EncryptInit_ex(&ctx, cipher, NULL, key, NULL) != 1) {
            printf("���ܳ�ʼ������\n");
            return -1;
        }

        char* in = argv[i];
        int inl = strlen(in);

        unsigned char inter[LEN];
        bzero(inter, LEN);
        int interl = 0;

        if (EVP_EncryptUpdate(&ctx, inter, &interl, (unsigned char*)in, inl) != 1) {
            printf("���ܸ��´���\n");
            return -2;
        }
        int len = interl;
        if (EVP_EncryptFinal_ex(&ctx, inter+len, &interl) != 1) {
            printf("���ܽ�������\n");
            return -3;
        }
        len += interl;
        EVP_CIPHER_CTX_cleanup(&ctx);

        //2. Base64����
        EVP_ENCODE_CTX ectx;
        EVP_EncodeInit(&ectx);

        unsigned char out[LEN];
        bzero(out, LEN);
        int outl = 0;

        EVP_EncodeUpdate(&ectx, out, &outl, inter, len);
        len = outl;
        EVP_EncodeFinal(&ectx, out+len, &outl);
        len += outl;

        if (out[len-1] == 10) out[len-1] = '\0';
        printf("%s", out);
        if (i < argc - 1) printf(" ");
    }

    printf("\n");
    return 0;
}
