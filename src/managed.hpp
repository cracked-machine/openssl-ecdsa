#ifndef __MANAGED_HPP__
#define __MANAGED_HPP__

#include <openssl/bio.h>
#include <openssl/cms.h>

#include <exception>
#include <memory>
#include <iostream>

// https://godbolt.org/z/aer7K5fb1

template<class T>
class OpensslSharedPtr
{
public:
    OpensslSharedPtr(T* _p) { /* override using explicit specialization */ };
    void nullptr_handler(T* _p) { if (!_p) { std::cout << "nullptr Error" << std::endl; } }
    T* get() { return m_ptr.get(); };
private:
    std::shared_ptr<T> m_ptr;
};

// specialise and override constructor that calls pointer checker 
// and adds specialised deleter for BIO type.
template<> OpensslSharedPtr<BIO>::OpensslSharedPtr(BIO* _p) { 
    nullptr_handler(_p);
     // Since shared_ptr sets the deleter during initialization we can use lambdas
    m_ptr = std::shared_ptr<BIO>(_p, [](BIO* _p) 
    { 
        if (_p) BIO_free(_p); 
    });
 }; 

template class OpensslSharedPtr<BIO>;

////////////////////////////////////////////////

// deleters for unique_ptr must already be declared for member template declaration (m_ptr)
struct OpensslDeleter;

template<class T>
class OpensslUniquePtr
{
public:
    OpensslUniquePtr(T* _p) { /* override using explicit specialization */ };
    void nullptr_handler(T* _p) { if (!_p) { std::cout << "invalid nullptr arg" << std::endl; } }
    T* get() { return m_ptr.get(); }
private:
    std::unique_ptr<T, OpensslDeleter> m_ptr;
};

// deleters for unique_ptr must already be defined for explicit specialization
struct OpensslDeleter {
    void operator()(BIO *_p) { BIO_free(_p); }
};

template<> OpensslUniquePtr<BIO>::OpensslUniquePtr(BIO* _p) {    
    nullptr_handler(_p); 
    m_ptr = std::unique_ptr<BIO, OpensslDeleter>(_p);
}; 

template class OpensslUniquePtr<BIO>;

#endif // __MANAGED_HPP__