#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdlib.h>

#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
// #include <openssl/x509.h>

int read_binary_file(std::filesystem::path path, std::vector<uint8_t> &in)
{
    if (not std::filesystem::exists(path)) { return -1; }
    // open filestream and write to "in" param
    std::ifstream ifs(path, std::ios::in | std::ios::binary);
    in.assign((std::istreambuf_iterator<char>(ifs)), {});
    return 0;
}

int parse_signinfos()
{
    std::vector<uint8_t> cmd_der_bytes;
    [[maybe_unused]] int status;
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
        
        // iterate the signed attributes from the signer infos section
        for (int a = 0; a < CMS_signed_get_attr_count(si); ++a)
        {
            X509_ATTRIBUTE *attr = CMS_signed_get_attr(si, a);
            // print the signed attribute oid as string
            ASN1_OBJECT *attrObj = X509_ATTRIBUTE_get0_object(attr);
            std::cout << OBJ_nid2ln(OBJ_obj2nid(attrObj)) << std::endl;
            // print the signed attribute data type (int) and value (bytes)
            ASN1_TYPE *attrType = X509_ATTRIBUTE_get0_type(attr, 0);
            std::cout << "\t" << attrType->type << ": ";
            std::cout << attrType->value.asn1_string->data << std::endl;

            [[maybe_unused]] auto v = attrType->value;
            const ASN1_ITEM *item = NULL;
            [[maybe_unused]] void *thing = NULL;
            std::vector<unsigned char> buf(100);
            unsigned char *s = buf.data();
            switch(attrType->type)
            {
                case V_ASN1_SEQUENCE:
                    item = ASN1_ITEM_rptr(ASN1_ANY);
                    thing = ASN1_TYPE_unpack_sequence(item, attrType);
                    
                    ASN1_STRING_to_UTF8(&s, (ASN1_STRING*)item);
                    
                    break;
                default:
                    break;

            };
            // ASN1_OBJECT *attrData;
            // X509_ATTRIBUTE_get0_data(attr, a, attrType->type, attrData);
            // std::vector<char> text(30);
            // int len = i2t_ASN1_OBJECT(text.data(), text.size(), attrData);
            // std::cout << text.data() << "(" << len << ")" << std::endl;
        }
    }

    return 0;
}



int main()
{
    // /workspaces/openssl-ecdsa/bash/out/signedtext.der

}