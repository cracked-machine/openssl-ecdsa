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

openssl ecparam -name ${CURVE} -out ${WORKDIR}/${KEYPARAMS}
openssl req -x509 -nodes -days 3650 -newkey  ec:${WORKDIR}/${KEYPARAMS} -keyout ${WORKDIR}/${KEYFILE} -out ${WORKDIR}/${CERTFILE}

# # sign and verify in PEM format
# openssl cms -sign -binary -in ${WORKDIR}/${PT} -out ${WORKDIR}/${CT} -inkey ${WORKDIR}/${KEYFILE} -signer ${WORKDIR}/${CERTFILE} -nodetach
# openssl cms -verify -in ${WORKDIR}/${CT} -out ${WORKDIR}/plaintext2.dat -CAfile ${WORKDIR}/${CERTFILE} 

# # sign and verify in DER format
# openssl cms -sign -binary -in ${WORKDIR}/${PT} -out ${WORKDIR}/signedtext.der -inkey ${WORKDIR}/${KEYFILE} -signer ${WORKDIR}/${CERTFILE} -nodetach -outform DER
# openssl cms -verify -in ${WORKDIR}/signedtext.der -out ${WORKDIR}/plaintext2.dat -CAfile ${WORKDIR}/${CERTFILE} -inform DER

openssl cms \
    -sign \
    -signer ${WORKDIR}/${CERTFILE} \
    -inkey ${WORKDIR}/${KEYFILE} \
    -nodetach \
    -outform DER \
    -in  ${WORKDIR}/${PT} \
    -out ${WORKDIR}/${CT} \
    -nosmimecap 

openssl cms -verify -in ${WORKDIR}/${CT} -out ${WORKDIR}/plaintext2.dat -CAfile ${WORKDIR}/${CERTFILE} -inform DER


openssl cms \
    -inform DER \
    -in ${WORKDIR}/${CT} \
    -cmsout \
    -print \
    > ${WORKDIR}/cms-contentinfo.txt