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

# generate X509 certificate and (unencrypted) private key using the ECDSA params
openssl req \
    -x509 \
    -noenc \
    -newkey ec:${WORKDIR}/${KEYPARAMS} \
    -keyout ${WORKDIR}/${KEYFILE} \
    -out ${WORKDIR}/${CERTFILE}


openssl cms \
    -sign \
    -nocerts \
    -signer ${WORKDIR}/${CERTFILE} \
    -inkey ${WORKDIR}/${KEYFILE} \
    -nodetach \
    -outform DER \
    -in  ${WORKDIR}/${PT} \
    -out ${WORKDIR}/${CT} \
    -nosmimecap 

openssl cms \
    -verify \
    -nointern \
    -in ${WORKDIR}/${CT} \
    -out ${WORKDIR}/plaintext2.dat \
    -CAfile ${WORKDIR}/${CERTFILE} \
    -certfile ${WORKDIR}/${CERTFILE} \
    -inform DER


openssl cms \
    -inform DER \
    -in ${WORKDIR}/${CT} \
    -cmsout \
    -print \
    > ${WORKDIR}/cms-contentinfo.txt