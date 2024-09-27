#!/bin/bash

PAYLOAD=plaintext.txt

WORKDIR=/workspaces/openssl-ecdsa/scripts/cms-out
rm -rf ${WORKDIR} || true
mkdir -p ${WORKDIR}

echo -n $'\xDE\xAD\xBE\xEF' > ${WORKDIR}/${PAYLOAD}

openssl ecparam -name prime256v1 -out ${WORKDIR}/p256-params.pem

openssl req -x509 -nodes -days 3650 -newkey  ec:${WORKDIR}/p256-params.pem -keyout ${WORKDIR}/p256-key.pem -out ${WORKDIR}/p256-cert.pem

# sign and verify in PEM format
openssl cms -sign -binary -in ${WORKDIR}/${PAYLOAD} -out ${WORKDIR}/signedtext.pem -inkey ${WORKDIR}/p256-key.pem -signer ${WORKDIR}/p256-cert.pem -nodetach
openssl cms -verify -in ${WORKDIR}/signedtext.pem -out ${WORKDIR}/plaintext2.dat -CAfile ${WORKDIR}/p256-cert.pem 

# sign and verify in DER format
openssl cms -sign -binary -in ${WORKDIR}/${PAYLOAD} -out ${WORKDIR}/signedtext.der -inkey ${WORKDIR}/p256-key.pem -signer ${WORKDIR}/p256-cert.pem -nodetach -outform DER
openssl cms -verify -in ${WORKDIR}/signedtext.der -out ${WORKDIR}/plaintext2.dat -CAfile ${WORKDIR}/p256-cert.pem -inform DER

