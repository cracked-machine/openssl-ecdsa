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
            ASN1_OBJECT *attrObj = X509_ATTRIBUTE_get0_object(attr);
            std::cout << OBJ_nid2ln(OBJ_obj2nid(attrObj)) << std::endl;
            ASN1_TYPE *attrType = X509_ATTRIBUTE_get0_type(attr, 0);
            std::cout << "\t" << attrType->type << ": ";
            std::cout << attrType->value.asn1_string->data << std::endl;
            // /usr/include/openssl/asn1.h
            // **** ASN.1 tag values ****
            // V_ASN1_EOC                      0
            // V_ASN1_BOOLEAN                  1 /**/
            // V_ASN1_INTEGER                  2
            // V_ASN1_BIT_STRING               3
            // V_ASN1_OCTET_STRING             4
            // V_ASN1_NULL                     5
            // V_ASN1_OBJECT                   6
            // V_ASN1_OBJECT_DESCRIPTOR        7
            // V_ASN1_EXTERNAL                 8
            // V_ASN1_REAL                     9
            // V_ASN1_ENUMERATED               10
            // V_ASN1_UTF8STRING               12
            // V_ASN1_SEQUENCE                 16
            // V_ASN1_SET                      17
            // V_ASN1_NUMERICSTRING            18 /**/
            // V_ASN1_PRINTABLESTRING          19
            // V_ASN1_T61STRING                20
            // V_ASN1_TELETEXSTRING            20/* alias */
            // V_ASN1_VIDEOTEXSTRING           21 /**/
            // V_ASN1_IA5STRING                22
            // V_ASN1_UTCTIME                  23
            // V_ASN1_GENERALIZEDTIME          24 /**/
            // V_ASN1_GRAPHICSTRING            25 /**/
            // V_ASN1_ISO64STRING              26 /**/
            // V_ASN1_VISIBLESTRING            26/* alias */
            // V_ASN1_GENERALSTRING            27 /**/
            // V_ASN1_UNIVERSALSTRING          28 /**/
            // V_ASN1_BMPSTRING                30
            auto v = attrType->value;
            const ASN1_ITEM *item = NULL;
            void *thing = NULL;
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