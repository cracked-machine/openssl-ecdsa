#include <openssl/bn.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/ec.h>

#include <iostream>
#include <stdlib.h>
#include <memory>

#include "parser_utils.hpp"

// managed by lambda deleter
using ManagedCMS = std::shared_ptr<CMS_ContentInfo>;

int get_cms(ManagedCMS &cms_ptr, std::string path)
{
    int res = 0;

    BIO* filebio = BIO_new_file(path.c_str(), "r");
    res = flush_error_buffer();
    
    // set the deleter now, for when the application exits
    cms_ptr = ManagedCMS(
        d2i_CMS_bio(filebio, nullptr),
        [](CMS_ContentInfo *p) { CMS_ContentInfo_free(p); }
    );

    // cleanup
    BIO_free(filebio);

    return res;
}

int parse_signinfos(ManagedCMS &mmanagedcms)
{
    unsigned int flags = CMS_NO_SIGNER_CERT_VERIFY;
    if( 1 != CMS_verify(mmanagedcms.get(), NULL, NULL, NULL, NULL, flags)) { std::terminate(); }
    
    auto *si_stack = CMS_get0_SignerInfos(mmanagedcms.get());
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
            u8_vector buf(100);
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
            // i8_vector text(30);
            // int len = i2t_ASN1_OBJECT(text.data(), text.size(), attrData);
            // std::cout << text.data() << "(" << len << ")" << std::endl;
        }
    }

    return 0;
}

// if the eContent contains 
int parse_encaps_octet_bytes(u8_vector &inout)
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

int parse_signerinfos_signature(
    ManagedCMS mmanagedcms,
    i8_vector &rbytesout, 
    i8_vector &sbytesout)
{
    int res = 0;

    auto *si_stack = CMS_get0_SignerInfos(mmanagedcms.get());
    res = flush_error_buffer();
    for(int i = 0; i < sk_CMS_SignerInfo_num(si_stack); ++i)
    {
        auto *si = sk_CMS_SignerInfo_value(si_stack, i);

        // get the signature
        ASN1_OCTET_STRING *sig_octet_str = CMS_SignerInfo_get0_signature(si);
        const unsigned char  *raw_sig_octets = sig_octet_str->data;
        ASN1_TYPE *sig_octet_str_subseq = d2i_ASN1_TYPE(nullptr, &raw_sig_octets, sig_octet_str->length);
        res = flush_error_buffer();
        
        const unsigned char *raw_sig_seq = sig_octet_str_subseq->value.sequence->data;
        ECDSA_SIG* ecdsa_sig = d2i_ECDSA_SIG(nullptr, &raw_sig_seq, sig_octet_str_subseq->value.sequence->length);
        res = flush_error_buffer();
        
        const BIGNUM *bn_rbytes = ECDSA_SIG_get0_r(ecdsa_sig);
        res = flush_error_buffer();
        auto raw_rbytes = BN_bn2hex(bn_rbytes);
        auto len_rbytes = BN_num_bytes(bn_rbytes);
        rbytesout = i8_vector(raw_rbytes, raw_rbytes + len_rbytes *sizeof (char) );
        std::free(raw_rbytes);

        const BIGNUM *bn_sbytes = ECDSA_SIG_get0_s(ecdsa_sig);
        res = flush_error_buffer();
        auto raw_sbytes = BN_bn2hex(bn_sbytes);
        auto len_sbytes = BN_num_bytes(bn_sbytes);
        sbytesout = i8_vector(raw_sbytes, raw_sbytes + len_sbytes *sizeof (char) );
        std::free(raw_sbytes);

        u8_vector octetbytes = u8_vector(
        sig_octet_str->data, 
        sig_octet_str->data + sig_octet_str->length * sizeof(unsigned char));
        print_vector_bytes(octetbytes);
        
        //cleanup
        ECDSA_SIG_free(ecdsa_sig);
        ASN1_TYPE_free(sig_octet_str_subseq);
    }
    return res;
}

int parse_signerinfos_signature_ident(
    ManagedCMS &mmanagedcms,
    std::string &algotypeout)
{
    int res = 0;
    
    auto *si_stack = CMS_get0_SignerInfos(mmanagedcms.get());
    res = flush_error_buffer();
    for(int i = 0; i < sk_CMS_SignerInfo_num(si_stack); ++i)
    {
        auto *si = sk_CMS_SignerInfo_value(si_stack, i);

        X509_ALGOR *x509_algo;
        CMS_SignerInfo_get0_algs(si, nullptr, nullptr, nullptr, &x509_algo);
    
        algotypeout.resize(100);
        i2t_ASN1_OBJECT(algotypeout.data(), algotypeout.size(), (ASN1_OBJECT *)x509_algo->algorithm);
        algotypeout.shrink_to_fit();
        res = flush_error_buffer();
    
    }
    return res;
}

int parse_econtent(ManagedCMS &mmanagedcms, u8_vector &out)
{
    int res = 0;

    // CMS_get0_content does NOT require cleanup/free
    ASN1_OCTET_STRING **pp_content_octect = CMS_get0_content(mmanagedcms.get());
    res = flush_error_buffer();

    ASN1_OCTET_STRING *asn1_octet_str = *pp_content_octect;
    if(!asn1_octet_str) { return -1; }

    out = u8_vector(
        asn1_octet_str->data, 
        asn1_octet_str->data + asn1_octet_str->length * sizeof(unsigned char));

    return res;
}

int main()
{
    int result = 0;

    ManagedCMS mmanagedcms;
    get_cms(
        mmanagedcms,
        "/workspaces/openssl-ecdsa/scripts/cms-out/signedtext.der"
    );

    u8_vector content_bytes;
    result = parse_econtent(mmanagedcms, content_bytes);
    
    print_vector_bytes(content_bytes);
    result = parse_encaps_octet_bytes(content_bytes);
    
    std::string algoident;
    result = parse_signerinfos_signature_ident(mmanagedcms, algoident);
    std::cout << algoident << std::endl;

    i8_vector rbytes;
    i8_vector sbytes;
    result = parse_signerinfos_signature(mmanagedcms, rbytes, sbytes);
    print_vector_bytes(rbytes);
    print_vector_bytes(sbytes);

    return result;

}