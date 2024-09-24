#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>

#include <openssl/cms.h>
#include <openssl/bio.h>

int read_binary_file(std::filesystem::path path, std::vector<uint8_t> &in)
{
    if (not std::filesystem::exists(path)) { return -1; }
    // open filestream and write to "in" param
    std::ifstream ifs(path, std::ios::in | std::ios::binary);
    in.assign((std::istreambuf_iterator<char>(ifs)), {});
    return 0;
}

int main()
{
    // /workspaces/openssl-ecdsa/bash/out/signedtext.der
    std::vector<uint8_t> cmd_der_bytes;
    int status;
    status = read_binary_file(
        std::filesystem::path("/workspaces/openssl-ecdsa/bash/out/signedtext.der"), 
        cmd_der_bytes
    );
    
    BIO *bio = BIO_new_mem_buf(cmd_der_bytes.data(), cmd_der_bytes.size());
    if (!bio) { std::terminate(); }

    CMS_ContentInfo *cms = d2i_CMS_bio(bio, NULL);
    if (!cms) {std::terminate(); }

    unsigned int flags = CMS_NO_SIGNER_CERT_VERIFY;
    if( 1 != CMS_verify(cms, NULL, NULL, NULL, NULL, flags)) { std::terminate(); }
    
    auto *si_stack = CMS_get0_SignerInfos(cms);
    for(int i = 0; i < sk_CMS_SignerInfo_num(si_stack); ++i)
    {
        auto *si = sk_CMS_SignerInfo_value(si_stack, i);
        
        for (int a = 0; a < CMS_signed_get_attr_count(si); ++a)
        {
            X509_ATTRIBUTE *attr = CMS_signed_get_attr(si, a);
            ASN1_TYPE *ttmp = X509_ATTRIBUTE_get0_type(attr, 0);
            std::cout << ttmp->value.asn1_string->data << std::endl;
            std::cout << ttmp->value.asn1_string->length << std::endl;
        }
        int stop = 2;
    }
    // CMS_signed_get_attr_count()

    return 0;
}