#!/usr/bin/env bash

certtool --generate-privkey > ./tests/resources/cert/data/key.pem
certtool --generate-self-signed \
  --load-privkey ./tests/resources/cert/data/key.pem \
  --template ./tests/resources/cert/ca.info \
  --outfile ./tests/resources/cert/data/cert.pem
