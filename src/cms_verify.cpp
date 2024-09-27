#include <vector>
#include <iostream>
#include <filesystem>

#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
// #include "../dep/openssl/crypto/cms/cms_local.h" /* for d.signedData and d.envelopedData */

/*
    * Test data generated using:
    * openssl cms -sign -md sha256 -signer ./test/certs/rootCA.pem -inkey \
    * ./test/certs/rootCA.key -nodetach -outform DER -in ./in.txt -out out.der \
    * -nosmimecap
    */

   
CMS_ContentInfo *read_rsa_signed_cms_file()
{
    std::vector<unsigned char> cms_data = {
        0x30, 0x82, 0x05, 0xc5, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0,
        0x82, 0x05, 0xb6, 0x30, 0x82, 0x05, 0xb2, 0x02,
        0x01, 0x01, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x30, 0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x0f,
        0x04, 0x0d, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
        0x57, 0x6f, 0x72, 0x6c, 0x64, 0x0d, 0x0a, 0xa0,
        0x82, 0x03, 0x83, 0x30, 0x82, 0x03, 0x7f, 0x30,
        0x82, 0x02, 0x67, 0xa0, 0x03, 0x02, 0x01, 0x02,
        0x02, 0x09, 0x00, 0x88, 0x43, 0x29, 0xcb, 0xc2,
        0xeb, 0x15, 0x9a, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41,
        0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
        0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65,
        0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
        0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
        0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74,
        0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74,
        0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74,
        0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35,
        0x30, 0x37, 0x30, 0x32, 0x31, 0x33, 0x31, 0x35,
        0x31, 0x31, 0x5a, 0x17, 0x0d, 0x33, 0x35, 0x30,
        0x37, 0x30, 0x32, 0x31, 0x33, 0x31, 0x35, 0x31,
        0x31, 0x5a, 0x30, 0x56, 0x31, 0x0b, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41,
        0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
        0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65,
        0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
        0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
        0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74,
        0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74,
        0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74,
        0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
        0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
        0x01, 0x01, 0x00, 0xc0, 0xf1, 0x6b, 0x77, 0x88,
        0xac, 0x35, 0xdf, 0xfb, 0x73, 0x53, 0x2f, 0x92,
        0x80, 0x2f, 0x74, 0x16, 0x32, 0x4d, 0xf5, 0x10,
        0x20, 0x6f, 0x6c, 0x3a, 0x8e, 0xd1, 0xdc, 0x6b,
        0xe1, 0x2e, 0x3e, 0xc3, 0x04, 0x0f, 0xbf, 0x9b,
        0xc4, 0xc9, 0x12, 0xd1, 0xe4, 0x0b, 0x45, 0x97,
        0xe5, 0x06, 0xcd, 0x66, 0x3a, 0xe1, 0xe0, 0xe2,
        0x2b, 0xdf, 0xa2, 0xc4, 0xec, 0x7b, 0xd3, 0x3d,
        0x3c, 0x8a, 0xff, 0x5e, 0x74, 0xa0, 0xab, 0xa7,
        0x03, 0x6a, 0x16, 0x5b, 0x5e, 0x92, 0xc4, 0x7e,
        0x5b, 0x79, 0x8a, 0x69, 0xd4, 0xbc, 0x83, 0x5e,
        0xae, 0x42, 0x92, 0x74, 0xa5, 0x2b, 0xe7, 0x00,
        0xc1, 0xa9, 0xdc, 0xd5, 0xb1, 0x53, 0x07, 0x0f,
        0x73, 0xf7, 0x8e, 0xad, 0x14, 0x3e, 0x25, 0x9e,
        0xe5, 0x1e, 0xe6, 0xcc, 0x91, 0xcd, 0x95, 0x0c,
        0x80, 0x44, 0x20, 0xc3, 0xfd, 0x17, 0xcf, 0x91,
        0x3d, 0x63, 0x10, 0x1c, 0x14, 0x5b, 0xfb, 0xc3,
        0xa8, 0xc1, 0x88, 0xb2, 0x77, 0xff, 0x9c, 0xdb,
        0xfc, 0x6a, 0x44, 0x44, 0x44, 0xf7, 0x85, 0xec,
        0x08, 0x2c, 0xd4, 0xdf, 0x81, 0xa3, 0x79, 0xc9,
        0xfe, 0x1e, 0x9b, 0x93, 0x16, 0x53, 0xb7, 0x97,
        0xab, 0xbe, 0x4f, 0x1a, 0xa5, 0xe2, 0xfa, 0x46,
        0x05, 0xe4, 0x0d, 0x9c, 0x2a, 0xa4, 0xcc, 0xb9,
        0x1e, 0x21, 0xa0, 0x6c, 0xc4, 0xab, 0x59, 0xb0,
        0x40, 0x39, 0xbb, 0xf9, 0x88, 0xad, 0xfd, 0xdf,
        0x8d, 0xb4, 0x0b, 0xaf, 0x7e, 0x41, 0xe0, 0x21,
        0x3c, 0xc8, 0x33, 0x45, 0x49, 0x84, 0x2f, 0x93,
        0x06, 0xee, 0xfd, 0x4f, 0xed, 0x4f, 0xf3, 0xbc,
        0x9b, 0xde, 0xfc, 0x25, 0x5e, 0x55, 0xd5, 0x75,
        0xd4, 0xc5, 0x7b, 0x3a, 0x40, 0x35, 0x06, 0x9f,
        0xc4, 0x84, 0xb4, 0x6c, 0x93, 0x0c, 0xaf, 0x37,
        0x5a, 0xaf, 0xb6, 0x41, 0x4d, 0x26, 0x23, 0x1c,
        0xb8, 0x02, 0xb3, 0x02, 0x03, 0x01, 0x00, 0x01,
        0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03,
        0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01,
        0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
        0x0e, 0x04, 0x16, 0x04, 0x14, 0x85, 0x56, 0x89,
        0x35, 0xe2, 0x9f, 0x00, 0x1a, 0xe1, 0x86, 0x03,
        0x0b, 0x4b, 0xaf, 0x76, 0x12, 0x6b, 0x33, 0x6d,
        0xfd, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
        0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x85, 0x56,
        0x89, 0x35, 0xe2, 0x9f, 0x00, 0x1a, 0xe1, 0x86,
        0x03, 0x0b, 0x4b, 0xaf, 0x76, 0x12, 0x6b, 0x33,
        0x6d, 0xfd, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
        0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x32, 0x0a,
        0xbf, 0x2a, 0x0a, 0xe2, 0xbb, 0x4f, 0x43, 0xce,
        0x88, 0xda, 0x5a, 0x39, 0x10, 0x37, 0x80, 0xbb,
        0x37, 0x2d, 0x5e, 0x2d, 0x88, 0xdd, 0x26, 0x69,
        0x9c, 0xe7, 0xb4, 0x98, 0x20, 0xb1, 0x25, 0xe6,
        0x61, 0x59, 0x6d, 0x12, 0xec, 0x9b, 0x87, 0xbe,
        0x57, 0xe1, 0x12, 0x05, 0xc5, 0x04, 0xf1, 0x17,
        0xce, 0x14, 0xb8, 0x1c, 0x92, 0xd4, 0x95, 0x95,
        0x2c, 0x5b, 0x28, 0x89, 0xfb, 0x72, 0x9c, 0x20,
        0xd3, 0x32, 0x81, 0xa8, 0x85, 0xec, 0xc8, 0x08,
        0x7b, 0xa8, 0x59, 0x5b, 0x3a, 0x6c, 0x31, 0xab,
        0x52, 0xe2, 0x66, 0xcd, 0x14, 0x49, 0x5c, 0xf3,
        0xd3, 0x3e, 0x62, 0xbc, 0x91, 0x16, 0xb4, 0x1c,
        0xf5, 0xdd, 0x54, 0xaa, 0x3c, 0x61, 0x97, 0x79,
        0xac, 0xe4, 0xc8, 0x43, 0x35, 0xc3, 0x0f, 0xfc,
        0xf3, 0x70, 0x1d, 0xaf, 0xf0, 0x9c, 0x8a, 0x2a,
        0x92, 0x93, 0x48, 0xaa, 0xd0, 0xe8, 0x47, 0xbe,
        0x35, 0xc1, 0xc6, 0x7b, 0x6d, 0xda, 0xfa, 0x5d,
        0x57, 0x45, 0xf3, 0xea, 0x41, 0x8f, 0x36, 0xc1,
        0x3c, 0xf4, 0x52, 0x7f, 0x6e, 0x31, 0xdd, 0xba,
        0x9a, 0xbc, 0x70, 0x56, 0x71, 0x38, 0xdc, 0x49,
        0x57, 0x0c, 0xfd, 0x91, 0x17, 0xc5, 0xea, 0x87,
        0xe5, 0x23, 0x74, 0x19, 0xb2, 0xb6, 0x99, 0x0c,
        0x6b, 0xa2, 0x05, 0xf8, 0x51, 0x68, 0xed, 0x97,
        0xe0, 0xdf, 0x62, 0xf9, 0x7e, 0x7a, 0x3a, 0x44,
        0x71, 0x83, 0x57, 0x28, 0x49, 0x88, 0x69, 0xb5,
        0x14, 0x1e, 0xda, 0x46, 0xe3, 0x6e, 0x78, 0xe1,
        0xcb, 0x8f, 0xb5, 0x98, 0xb3, 0x2d, 0x6e, 0x5b,
        0xb7, 0xf6, 0x93, 0x24, 0x14, 0x1f, 0xa4, 0xf6,
        0x69, 0xbd, 0xff, 0x4c, 0x52, 0x50, 0x02, 0xc5,
        0x43, 0x8d, 0x14, 0xe2, 0xd0, 0x75, 0x9f, 0x12,
        0x5e, 0x94, 0x89, 0xd1, 0xef, 0x77, 0x89, 0x7d,
        0x89, 0xd9, 0x9e, 0x76, 0x99, 0x24, 0x31, 0x82,
        0x01, 0xf7, 0x30, 0x82, 0x01, 0xf3, 0x02, 0x01,
        0x01, 0x30, 0x63, 0x30, 0x56, 0x31, 0x0b, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
        0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d,
        0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31,
        0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e,
        0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69,
        0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c,
        0x74, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f,
        0x74, 0x43, 0x41, 0x02, 0x09, 0x00, 0x88, 0x43,
        0x29, 0xcb, 0xc2, 0xeb, 0x15, 0x9a, 0x30, 0x0b,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0xa0, 0x69, 0x30, 0x18, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x09, 0x03, 0x31, 0x0b, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30,
        0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x09, 0x05, 0x31, 0x0f, 0x17, 0x0d,
        0x32, 0x30, 0x31, 0x32, 0x31, 0x31, 0x30, 0x39,
        0x30, 0x30, 0x31, 0x33, 0x5a, 0x30, 0x2f, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x09, 0x04, 0x31, 0x22, 0x04, 0x20, 0xb0, 0x80,
        0x22, 0xd3, 0x15, 0xcf, 0x1e, 0xb1, 0x2d, 0x26,
        0x65, 0xbd, 0xed, 0x0e, 0x6a, 0xf4, 0x06, 0x53,
        0xc0, 0xa0, 0xbe, 0x97, 0x52, 0x32, 0xfb, 0x49,
        0xbc, 0xbd, 0x02, 0x1c, 0xfc, 0x36, 0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x01,
        0x00, 0x37, 0x44, 0x39, 0x08, 0xb2, 0x19, 0x52,
        0x35, 0x9c, 0xd0, 0x67, 0x87, 0xae, 0xb8, 0x1c,
        0x80, 0xf4, 0x03, 0x29, 0x2e, 0xe3, 0x76, 0x4a,
        0xb0, 0x98, 0x10, 0x00, 0x9a, 0x30, 0xdb, 0x05,
        0x28, 0x53, 0x34, 0x31, 0x14, 0xbd, 0x87, 0xb9,
        0x4d, 0x45, 0x07, 0x97, 0xa3, 0x57, 0x0b, 0x7e,
        0xd1, 0x67, 0xfb, 0x4e, 0x0f, 0x5b, 0x90, 0xb2,
        0x6f, 0xe6, 0xce, 0x49, 0xdd, 0x72, 0x46, 0x71,
        0x26, 0xa1, 0x1b, 0x98, 0x23, 0x7d, 0x69, 0x73,
        0x84, 0xdc, 0xf9, 0xd2, 0x1c, 0x6d, 0xf6, 0xf5,
        0x17, 0x49, 0x6e, 0x9d, 0x4d, 0xf1, 0xe2, 0x43,
        0x29, 0x53, 0x55, 0xa5, 0x22, 0x1e, 0x89, 0x2c,
        0xaf, 0xf2, 0x43, 0x47, 0xd5, 0xfa, 0xad, 0xe7,
        0x89, 0x60, 0xbf, 0x96, 0x35, 0x6f, 0xc2, 0x99,
        0xb7, 0x55, 0xc5, 0xe3, 0x04, 0x25, 0x1b, 0xf6,
        0x7e, 0xf2, 0x2b, 0x14, 0xa9, 0x57, 0x96, 0xbe,
        0xbd, 0x6e, 0x95, 0x44, 0x94, 0xbd, 0xaf, 0x9a,
        0x6d, 0x77, 0x55, 0x5e, 0x6c, 0xf6, 0x32, 0x37,
        0xec, 0xef, 0xe5, 0x81, 0xb0, 0xe3, 0x35, 0xc7,
        0x86, 0xea, 0x47, 0x59, 0x38, 0xb6, 0x16, 0xfb,
        0x1d, 0x10, 0x55, 0x48, 0xb1, 0x44, 0x33, 0xde,
        0xf6, 0x29, 0xbe, 0xbf, 0xbc, 0x71, 0x3e, 0x49,
        0xba, 0xe7, 0x9f, 0x4d, 0x6c, 0xfb, 0xec, 0xd2,
        0xe0, 0x12, 0xa9, 0x7c, 0xc9, 0x9a, 0x7b, 0x85,
        0x83, 0xb8, 0xca, 0xdd, 0xf6, 0xb7, 0x15, 0x75,
        0x7b, 0x4a, 0x69, 0xcf, 0x0a, 0xc7, 0x80, 0x01,
        0xe7, 0x94, 0x16, 0x7f, 0x8d, 0x3c, 0xfa, 0x1f,
        0x05, 0x71, 0x76, 0x15, 0xb0, 0xf6, 0x61, 0x30,
        0x58, 0x16, 0xbe, 0x1b, 0xd1, 0x93, 0xc4, 0x1a,
        0x91, 0x0c, 0x48, 0xe2, 0x1c, 0x8e, 0xa5, 0xc5,
        0xa7, 0x81, 0x44, 0x48, 0x3b, 0x10, 0xc2, 0x74,
        0x07, 0xdf, 0xa8, 0xae, 0x57, 0xee, 0x7f, 0xe3,
        0x6a
    };

    // auto *derbio = BIO_new_file("cms.der", "wb");
    // BIO_write(derbio, cms_data.data(), cms_data.size());
    // BIO_free(derbio);

    auto *bio = BIO_new_mem_buf(cms_data.data(), cms_data.size());
    auto *cms = d2i_CMS_bio(bio, NULL);
    return cms;
}

CMS_ContentInfo *read_secp384r1_signed_cms()
{
    std::vector<unsigned char> cms_data;
    std::filesystem::path path("/workspaces/openssl-ecdsa/scripts/cms-out/signedtext.der");
    if (!std::filesystem::exists(path)) {
        std::cerr << "file not found:\n\t" << path.string() << "\nPlease run /workspaces/openssl-ecdsa/scripts/cms.sh first!" << std::endl;
    }
    auto *derbio = BIO_new_file(path.c_str(), "rb");
    auto *cms = d2i_CMS_bio(derbio, NULL);
    BIO_free(derbio);
    return cms;
}


int main()
{
    auto *errbio = BIO_new_file("err.log", "w");

    auto *cms = read_secp384r1_signed_cms();

    unsigned int flags = CMS_NO_SIGNER_CERT_VERIFY;
    int res = 0;
    
    res = CMS_verify(cms, NULL, NULL, NULL, NULL, flags);
    
    auto *si_stack = CMS_get0_SignerInfos(cms);
    for(int i = 0; i < sk_CMS_SignerInfo_num(si_stack); ++i)
    {
        auto *si = sk_CMS_SignerInfo_value(si_stack, i);
        auto *sig = CMS_SignerInfo_get0_signature(si);
        auto *mctx = CMS_SignerInfo_get0_md_ctx(si);
        auto *pctx = CMS_SignerInfo_get0_pkey_ctx(si);
                
        res = CMS_SignerInfo_verify(si);
        res = CMS_SignerInfo_verify_content(si, nullptr);
    }    
    // auto b = CMS_SignedData_verify(cms->d.signedData, NULL, NULL, NULL, NULL, NULL, flags, NULL, NULL);
    // auto *sd = cms->d.signedData;

    ERR_print_errors(errbio);
    BIO_flush(errbio);
    BIO_free(errbio);   // this closes the FILE stream
    return 0;    
}