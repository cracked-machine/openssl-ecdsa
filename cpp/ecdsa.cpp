
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string>
#include <vector>
#include <assert.h>


static int sign_and_verify_deprecated()
{
    const std::string hashstr("c7fbca202a95a570285e3d700eb04ca2");
    auto dgst = std::vector<unsigned char>(hashstr.data(), hashstr.data() + hashstr.length() + 1);

    int function_status = -1;
    EC_KEY *eckey=EC_KEY_new();
    if (NULL == eckey)
    {
        printf("Failed to create new EC Key\n");
        function_status = -1;
    }
    else
    {
        EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp192k1);
        if (NULL == ecgroup)
        {
            printf("Failed to create new EC Group\n");
            function_status = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(eckey,ecgroup);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status = -1;
            }
            else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(eckey);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status = -1;
                }
                else
                {
                    
                    ECDSA_SIG *signature = ECDSA_do_sign(dgst.data(), dgst.size(), eckey);
                    if (NULL == signature)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status = -1;
                    }
                    else
                    {

                        int verify_status = ECDSA_do_verify(dgst.data(), dgst.size(), signature, eckey);
                        const int verify_success = 1;
                        if (verify_success != verify_status)
                        {
                            printf("Failed to verify EC Signature\n");
                            function_status = -1;
                        }
                        else
                        {
                            printf("Verifed EC Signature (ECDSA_do_verify)\n");
                            function_status = 1;
                        }
                    }
                }
            }
            EC_GROUP_free(ecgroup);
        }
        EC_KEY_free(eckey);
    }

  return function_status;
}

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
    
    int status = sign_and_verify_deprecated();
    status = sign_and_verify();
    return(0) ;
}