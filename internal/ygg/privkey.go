package ygg

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
)

// OpenPrivateKey generates or opens existing private key
func OpenPrivateKey(name string) (priv *rsa.PrivateKey, err error) {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Size() == 0 {
		priv, err = rsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())), 4096)
		if err != nil {
			return nil, err
		}

		err = pem.Encode(f, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})
		if err != nil {
			return nil, err
		}

		return priv, nil
	}

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(bs)

	priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return priv, nil
}
