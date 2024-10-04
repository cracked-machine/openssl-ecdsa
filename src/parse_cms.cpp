#include <openssl/types.h>
#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdlib.h>

#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>

#include "utils.hpp"
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

// if the eContent contains 
int parse_encaps_octet_bytes(std::vector<unsigned char> &inout)
{
    auto *raw_octet_str = (const unsigned char*)inout.data();

    long foundlen;
    int foundtag, foundclass;
    [[maybe_unused]] int foundtype = ASN1_get_object(
        &raw_octet_str, 
        &foundlen, 
        &foundtag, 
        &foundclass, 
        inout.size()
    );
    return flush_error_buffer();
    
}

int parse_signerinfos_signature(std::vector<unsigned char> &out)
{
    int res = 0;

    BIO* filebio = BIO_new_file("/workspaces/openssl-ecdsa/scripts/cms-out/signedtext.der", "r");
    res = flush_error_buffer();
    
    CMS_ContentInfo *cms_data = d2i_CMS_bio(filebio, nullptr);
    res = flush_error_buffer();

    auto *si_stack = CMS_get0_SignerInfos(cms_data);
    res = flush_error_buffer();
    for(int i = 0; i < sk_CMS_SignerInfo_num(si_stack); ++i)
    {
        auto *si = sk_CMS_SignerInfo_value(si_stack, i);
        // CMS_SignerInfo_get0_signature does NOT require cleanup/free
        ASN1_OCTET_STRING *sig_octets = CMS_SignerInfo_get0_signature(si);
        
        res = flush_error_buffer();

        out = std::vector<unsigned char>(
        sig_octets->data, 
        sig_octets->data + sig_octets->length * sizeof(unsigned char));
    }

    // cleanup
    CMS_ContentInfo_free(cms_data);
    BIO_free(filebio);

    return res;
}

int parse_econtent(std::vector<unsigned char> &out)
{
    int res = 0;

    BIO* filebio = BIO_new_file("/workspaces/openssl-ecdsa/scripts/cms-out/signedtext.der", "r");
    res = flush_error_buffer();
    
    CMS_ContentInfo *cms_data = d2i_CMS_bio(filebio, nullptr);
    res = flush_error_buffer();

    // CMS_get0_content does NOT require cleanup/free
    ASN1_OCTET_STRING **pp_content_octect = CMS_get0_content(cms_data);
    res = flush_error_buffer();

    ASN1_OCTET_STRING *asn1_octet_str = *pp_content_octect;
    if(!asn1_octet_str) { return -1; }

    out = std::vector<unsigned char>(
        asn1_octet_str->data, 
        asn1_octet_str->data + asn1_octet_str->length * sizeof(unsigned char));

    // cleanup
    CMS_ContentInfo_free(cms_data);
    BIO_free(filebio);

    return res;
}

int main()
{
    int result = 0;
    std::vector<unsigned char> content_bytes;
    result = parse_econtent(content_bytes);
    print_vector_bytes(content_bytes);
    result = parse_encaps_octet_bytes(content_bytes);
    
    std::vector<unsigned char> signature_bytes;
    result = parse_signerinfos_signature(signature_bytes);
    print_vector_bytes(signature_bytes);

    return result;

}