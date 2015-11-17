#!/bin/bash -e

N=32
hash () {
    (echo -n "$1"; head -c$N /dev/zero) | head -c$N | sha256sum | head -c64
}

xor=$(hash "a chaching layer for bitcoin")
secret="forked lightning"
hashed1=$(hash "$secret")
hashed2="988335089aea34fff1a5a4f98c2726fef8285e5647f6f83a18e347a2e1ece8bf"

#rm -f keygen.txt
rm -f input.txt proof.txt

if ! [ -e keygen.txt ]; then
  echo
  time ./test_lightning -m keygen > keygen.txt
  ls -l keygen.txt
fi

echo
cat keygen.txt | \
    time ./test_lightning -m proof -s "$secret" -h "$hashed0" -b "$hashed2" -x "$xor" > proof.txt
ls -l proof.txt

echo
cat keygen.txt proof.txt | \
    time ./test_lightning -m verify -h "$hashed1" -b "$hashed2" -x "${xor}"
