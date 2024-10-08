#include "parser_utils.hpp"
#include <iostream>

void process_errors(int result, std::string op)
{
    BIO* errbio = BIO_new_file("err.log", "w");
    if (result == 0)
    {
        std::cerr << "ERROR: " << op << std::endl; 
    }
    if (result == -1)
    {
        ERR_print_errors(errbio);
        std::cerr << "FATAL: "<< op << ". See err.log." << std::endl;
        std::terminate();
    }
    BIO_free(errbio);
}

// flush all errors from the buffer to stdout
int flush_error_buffer(bool abort_on_errors)
{
    int status = 0;
    i8_vector errbuf;
    unsigned long errcode = ERR_get_error();
    while(errcode > 0)
    {
        status = 1;
        std::cout << ERR_error_string(errcode, errbuf.data()) << std::endl;
        errcode = ERR_get_error();
    }
    if ((abort_on_errors) && (status))
        std::terminate();
    return status;
}


void print_asn1octet_bytes(ASN1_OCTET_STRING* in)
{
    u8_vector buf(in->data, in->data + in->length * sizeof(uint8_t));
    for(unsigned char &b: buf)
        std::cout << std::hex << static_cast<int>(b) << std::endl;
}

void print_raw_bytes(unsigned char* in, int len)
{
    u8_vector buf(in, in + len * sizeof(uint8_t));
    for(unsigned char &b: buf)
        std::cout << std::hex << static_cast<int>(b) << std::endl;
}

void print_vector_bytes(u8_vector& in)
{
    for(unsigned char &b: in)
        std::cout << std::hex << static_cast<int>(b);
    std::cout << std::endl;
}

void print_vector_bytes(i8_vector& in)
{
    for(char &b: in)
        std::cout << std::hex << static_cast<int>(b);
    std::cout << std::endl;
}