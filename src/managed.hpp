#ifndef __MANAGED_HPP__
#define __MANAGED_HPP__

#include <openssl/bio.h>
#include <openssl/cms.h>

#include <exception>
#include <memory>
#include <iostream>

template<class T>
class OpensslSharedPtr
{
public:
    OpensslSharedPtr(T* _p) {};
    ~OpensslSharedPtr() {};
    void checkptr(T* _p) { if (!_p) { std::cout << "nullptr Error" << std::endl; } }
    T* get() { return m_ptr.get(); };
private:
    std::shared_ptr<T> m_ptr;
};

// specialise and override constructor that calls pointer checker 
// and adds specialised deleter for BIO type.
template<> OpensslSharedPtr<BIO>::OpensslSharedPtr(BIO* _p) { 
    checkptr(_p);
    m_ptr = std::shared_ptr<BIO>(_p, [](BIO* _p) 
    { 
        if (_p) BIO_free(_p); 
    });
 }; 

template class OpensslSharedPtr<BIO>;

////////////////////////////////////////////////

struct OpensslDeleter {
    void operator()(BIO *_p) { BIO_free(_p); }
};

template<class T>
class OpensslUniquePtr
{
public:
    OpensslUniquePtr(T* _p) {};
    ~OpensslUniquePtr() {};
    void checkptr(T* _p) { if (!_p) { std::cout << "invalid nullptr arg" << std::endl; } }
    T* get() { return m_ptr.get(); }
private:

    std::unique_ptr<T, OpensslDeleter> m_ptr;
};

template<> OpensslUniquePtr<BIO>::OpensslUniquePtr(BIO* _p) {     
    m_ptr = std::unique_ptr<BIO, OpensslDeleter>(_p);
}; 

template class OpensslUniquePtr<BIO>;

#endif // __MANAGED_HPP__