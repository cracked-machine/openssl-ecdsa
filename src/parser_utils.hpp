#ifndef __UTILS_HPP__
#define __UTILS_HPP__

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

#include <string>
#include <vector>

using u8_vector = std::vector<unsigned char>;
using i8_vector = std::vector<char>;


void process_errors(int result, std::string op);

// flush all errors from the buffer to stdout
int flush_error_buffer(bool abort_on_errors = false);

void print_asn1octet_bytes(ASN1_OCTET_STRING* in);

void print_raw_bytes(unsigned char* in, int len);

void print_vector_bytes(u8_vector& in);

void print_vector_bytes(i8_vector& in);

// template void print_raw_bytes<const unsigned char>;

#endif