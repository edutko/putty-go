#!/usr/bin/env bash

PUTTYGEN=${PUTTYGEN:-$(which puttygen)}
if [ ! -f "$PUTTYGEN" ]
then
  echo "puttygen not found" >&2
  exit 1
fi

OUTDIR=$(dirname "$0")/../ppk/testdata
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

pwfile="$OUTDIR"/password
echo -n hunter2 > "$pwfile"

generate_keys() {
  keytype="$1"
  bits="$2"
  name="${keytype}"
  bits_arg=""
  if [ -n "$bits" ]
  then
    name="${keytype}-${bits}"
    bits_arg="-b ${bits}"
  fi
  rm -f "$OUTDIR/${name}*.ppk" "$OUTDIR/id_${name}" "$OUTDIR/v2-${name}*.ppk" || true
  "$PUTTYGEN" -q -t "$keytype" $bits_arg -C "puTTY ${name}" -o "$OUTDIR/${name}.ppk" --new-passphrase /dev/null
  "$PUTTYGEN" -q "$OUTDIR/${name}.ppk" -C "puTTY ${name} (encrypted)" -o "$OUTDIR/${name}-enc.ppk" --old-passphrase /dev/null --new-passphrase "$pwfile"

  "$PUTTYGEN" -q "$OUTDIR/${name}.ppk" -C "OpenSSH ${name}" -o "$OUTDIR/id_${name}" -O private-openssh-new --old-passphrase /dev/null --new-passphrase /dev/null

  "$PUTTYGEN" -q "$OUTDIR/${name}.ppk" -C "puTTY v2 ${name}" --ppk-param version=2 -o "$OUTDIR/v2-${name}.ppk" --old-passphrase /dev/null --new-passphrase /dev/null
  "$PUTTYGEN" -q "$OUTDIR/${name}.ppk" -C "puTTY v2 ${name} (encrypted)" --ppk-param version=2 -o "$OUTDIR/v2-${name}-enc.ppk" --old-passphrase /dev/null --new-passphrase "$pwfile"
}

keytype=dsa
for bits in 1024 2048
do
  generate_keys "$keytype" "$bits"
done

keytype=ecdsa
for bits in 256 384 521
do
  generate_keys "$keytype" "$bits"
done

for keytype in ed25519 ed448
do
  generate_keys "$keytype"
done

keytype=rsa
bits=2048
generate_keys "$keytype" "$bits"
