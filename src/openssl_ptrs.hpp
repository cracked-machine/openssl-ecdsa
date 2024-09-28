#ifndef __OPENSSL_PTRS__
#define __OPENSSL_PTRS__

#include <vector>
#include <memory>
#include <exception>

#include <openssl/cms.h>
#include <openssl/bio.h>


struct OpensslDeleter {
    void operator()(CMS_ContentInfo *_p) { CMS_ContentInfo_free(_p); }
    void operator()(stack_st_CMS_SignerInfo *_p) { /* sk_CMS_SignerInfo_free(_p); */ }
    void operator()(CMS_SignerInfo *_p) {  /* don't free CMS_SignerInfo before CMS_ContentInfo */ }
    void operator()(stack_st_X509 *_p) { sk_X509_free(_p); }
    void operator()(X509 *_p) {  X509_free(_p); }
    void operator()(BIO *_p) { BIO_free(_p); }
};

using UniqueCmsContentInfo = std::unique_ptr<CMS_ContentInfo, OpensslDeleter>;
using UniqueCmsSignerInfoStack = std::unique_ptr<stack_st_CMS_SignerInfo, OpensslDeleter>;
using UniqueCmsSignerInfo = std::unique_ptr<CMS_SignerInfo, OpensslDeleter>;
using UniqueX509Stack = std::unique_ptr<stack_st_X509, OpensslDeleter>;
using UniqueX509 = std::unique_ptr<X509, OpensslDeleter>;
using UniqueBio = std::unique_ptr<BIO, OpensslDeleter>;

// class OpensslException : public std::exception {
//     std::string msg{"Oh dear"};
//     public:
//     const char * what () 
//     {
//         // backtrace()?
//         return msg.c_str();
//     }
// };


#endif // __OPENSSL_PTRS__