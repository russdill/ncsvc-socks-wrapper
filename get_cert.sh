#!/bin/bash

echo |
      openssl s_client -connect $1:443 2>&1 |
      sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' |
      openssl x509 -outform der > $2
