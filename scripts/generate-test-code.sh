#!/usr/bin/env bash

INDIR=$(dirname "$0")/../ppk/testdata


(
cd "$INDIR" || exit 1

echo 'var ppks = map[string]*PPK{'
for f in *.ppk
do
  version=$(grep -E '^PuTTY-User-Key-File' "$f" | sed -E -e 's/PuTTY-User-Key-File-//' -e 's/:.*//')
  encryption=$(grep -E '^Encryption:' "$f" | sed -E -e 's/Encryption: +//')

  echo '"'"$f"'": {'
  echo -n 'Version:      '
  echo -n "$version"
  echo ','

  echo -n 'Type:         "'
  echo -n  "$(grep -E '^PuTTY-User-Key-File' "$f" | sed -E -e 's/PuTTY-User-Key-File-.: *//')"
  echo '",'

  if [ "$encryption" == "none" ]
  then
    echo 'Encryption:   NoEncryption,'
  else
    echo 'Encryption:   AES256CBC,'
  fi

  echo -n 'Comment:      "'
  echo -n  "$(grep -E '^Comment:' "$f" | sed -E -e 's/Comment: *//')"
  echo '",'

  echo -n 'PublicBytes:  b64Bytes("'
  awk 'BEGIN {p=0;} /:/ {p=0;} /Public-Lines:/ {p=1;} /^[0-9A-Za-z+\/=]+$/ {if (p==1) printf "%s",$0;}' "$f"
  echo '"),'

  if  [ "$encryption" != "none" ] && [ "$version" == "3" ]
  then
    echo -n 'KeyDerivation:     '
    echo -n  "$(grep -E '^Key-Derivation:' "$f" | sed -E -e 's/Key-Derivation: *//')"
    echo ','

    echo -n 'Argon2Memory:      '
    echo -n  "$(grep -E '^Argon2-Memory:' "$f" | sed -E -e 's/Argon2-Memory: *//')"
    echo ','

    echo -n 'Argon2Passes:      '
    echo -n  "$(grep -E '^Argon2-Passes:' "$f" | sed -E -e 's/Argon2-Passes: *//')"
    echo ','

    echo -n 'Argon2Parallelism: '
    echo -n  "$(grep -E '^Argon2-Parallelism:' "$f" | sed -E -e 's/Argon2-Parallelism: *//')"
    echo ','

    echo -n 'Argon2Salt:        hexBytes("'
    echo -n  "$(grep -E '^Argon2-Salt:' "$f" | sed -E -e 's/Argon2-Salt: *//')"
    echo '"),'
  fi

  echo -n 'PrivateBytes: b64Bytes("'
  awk 'BEGIN {p=0;} /:/ {p=0;} /Private-Lines:/ {p=1;} /^[0-9A-Za-z+\/=]+$/ {if (p==1) printf "%s",$0;}' "$f"
  echo '"),'

  echo -n 'MAC:          hexBytes("'
  echo -n  "$(grep -E '^Private-MAC:' "$f" | sed -E -e 's/Private-MAC: *//')"
  echo '"),'

  echo '},'
done
echo '}'
) > ppks.go
