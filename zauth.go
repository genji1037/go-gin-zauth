package go_gin_zauth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"strconv"
	"time"
)

/*

Given:

- `t` = a token in bytestring format

Then:

- let `n` = current POSIX time
- let `x` = base64 decoded `t` parsed according to format spec.
- if the timestamp of `x` is < `n` then fail
- let `i` = the key index part of `x`
- let `k` = the public key at index `i`
- let `y` = `x` without `<signature> "."`
- verify the ed25519 signature of `y` using `k`

*/
var (
	sep  = []byte(".")
	dpre = []byte("d=")
	kpre = []byte("k=")
)

func Verify(t []byte, pubKeys []ed25519.PublicKey) error {

	n := time.Now().Unix()

	var x []byte
	_, err := base64.StdEncoding.Decode(x, t)
	if err != nil {
		return err
	}

	arr := bytes.Split(x, sep)
	if len(arr) < 7 {
		return fmt.Errorf("bad token format")
	}

	signature := arr[0]
	tsBs := bytes.Replace(arr[3], dpre, []byte{}, 1)
	ts, err := strconv.ParseInt(string(tsBs), 10, 64)
	if err != nil {
		return err
	}
	if ts < n {
		return fmt.Errorf("token expired")
	}

	iBs := bytes.Replace(arr[2], kpre, []byte{}, 1)
	i, err := strconv.ParseInt(string(iBs), 10, 64)
	if err != nil {
		return err
	}
	if int(i) > len(pubKeys) {
		return fmt.Errorf("invalid key index")
	}

	k := pubKeys[i-1]

	y := bytes.Replace(x, append(signature, sep...), []byte{}, 1)

	if !ed25519.Verify(k, y, signature) {
		return fmt.Errorf("bad signature")
	}

	return nil
}
