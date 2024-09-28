#!/bin/bash

PT=plaintext.txt
CT=signedtext.der
CURVE=secp384r1
KEYPARAMS=${CURVE}-params.pem
KEYFILE=${CURVE}-key.pem
CERTFILE=${CURVE}-cert.pem

WORKDIR=/workspaces/openssl-ecdsa/scripts/cms-out
rm -rf ${WORKDIR} || true
mkdir -p ${WORKDIR}

echo -n $'\xDE\xAD\xBE\xEF' > ${WORKDIR}/${PT}

# generate ECDSA parameters
openssl ecparam -name ${CURVE} -out ${WORKDIR}/${KEYPARAMS}

# generate a self-signed root CA (X509) and (unencrypted) private key using the ECDSA params
openssl req \
    -x509 \
    -noenc \
    -subj "/CN=GB\/emailAddress=admin@something.com/C=US/ST=Ohio/L=Columbus/O=Widgets Inc/OU=Some Unit" \
    -newkey ec:${WORKDIR}/${KEYPARAMS} \
    -keyout ${WORKDIR}/${KEYFILE} \
    -out ${WORKDIR}/${CERTFILE} \
    -verbose

# sign the CMS using the root CA and private key
openssl cms \
    -sign \
    -signer ${WORKDIR}/${CERTFILE} \
    -inkey ${WORKDIR}/${KEYFILE} \
    -nodetach \
    -outform DER \
    -in  ${WORKDIR}/${PT} \
    -out ${WORKDIR}/${CT} \
    -nosmimecap

# output the signed CMS data. Note the embedded certificate data
openssl cms \
    -inform DER \
    -in ${WORKDIR}/${CT} \
    -cmsout \
    -print \
    > ${WORKDIR}/cms-contentinfo.txt

# verify the signed CMS data using the embedded self-signed certificate
openssl cms \
    -verify \
    -noverify \
    -in ${WORKDIR}/${CT} \
    -out ${WORKDIR}/plaintext2.dat \
    -inform DER

