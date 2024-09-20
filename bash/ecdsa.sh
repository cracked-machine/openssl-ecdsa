#!/bin/bash

# options
HASHFUNC=sha256

# cryptkey files
SK=private.pem
VK=public.pem
DGST=hash
SIG=sig.bin

# the input payload to hash/sign/verify
PAYLOAD=payload.bin

# cleanup first
if [ -e ${SK} ]; then rm ${SK}; fi
if [ -e ${VK} ]; then rm ${VK}; fi
if [ -e ${DGST} ]; then rm ${HASH}; fi
if [ -e ${SIG} ]; then rm ${SIG}; fi
if [ -e ${PAYLOAD} ]; then rm ${PAYLOAD}; fi

# create a file containg some binary data
echo -n $'\xDE\xAD\xBE\xEF' > ${PAYLOAD}

# create public/private keys using
# NIST/X9.62/SECG curve over a 192 bit prime field
openssl ecparam -genkey -name prime192v3 -noout -out ${SK}
openssl ec -in ${SK} -pubout -out ${VK}

# create hash digest of the payload using SHA256
openssl dgst -binary -out ${DGST} -${HASHFUNC} ${PAYLOAD} 
# sign the hash digest using private key
openssl dgst -binary -sign ${SK} ${DGST} > ${SIG}

# # # verify the signature
# openssl rsautl -verify -in  ${SIG} -pubin -inkey ${VK} -asn1parse
# openssl pkeyutl -verify -in ${DGST} -sigfile ${SIG} -inkey ${SK}

# # verify
openssl dgst -${HASHFUNC} -verify ${VK} -signature ${SIG} ${DGST}