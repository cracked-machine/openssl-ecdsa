#!/bin/bash

openssl cms \
    -inform DER \
    -in /workspaces/openssl-ecdsa/src/cms.der \
    -cmsout \
    -print