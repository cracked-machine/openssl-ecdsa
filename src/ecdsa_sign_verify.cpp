

#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string>
#include <vector>
#include <assert.h>


#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <iostream>

int sign_and_verify()
{
    size_t hash_len = 33;
    const unsigned char hash[hash_len] = "c7fbca202a95a570285e3d700eb04ca2";
    size_t sig_len = 256;
    unsigned char sig[sig_len] = {0};

    // const std::string hashstr("c7fbca202a95a570285e3d700eb04ca2");
    // auto dgst = std::vector<unsigned char>(hashstr.data(), hashstr.data() + hashstr.length() + 1);
    // auto sig = std::vector<unsigned char>(256);

    EVP_PKEY *evp_key = EVP_EC_gen("prime192v3");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_key, NULL);
    int res = 0;
    if (EVP_PKEY_sign(ctx, sig, (size_t*)sig_len, hash, hash_len ) == 0 )
    {
        std::cout << "Failed to create signature!" << std::endl;
        std::terminate();
    }
    
    if (EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len))
    {
        std::cout << "Verified EC Signature (EVP_PKEY_verify)" << std::endl;
    }
    else
    {
        std::cout << "Failed to verify signature!" << std::endl;
        std::terminate();
    }
    return res;
}

int main( int argc , char * argv[] )
{
    int status = sign_and_verify();
    return(status) ;
}