package sign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/dustinxie/ecc"
)

/*
cosmos1tzzt5ppajx5dts6hnuge0tv4y6hx27u82r5fs2
hour luxury pizza relief material tail embrace motion foam book lyrics blur code mountain version pause mobile parrot glow worth happy ill ceiling almost <nil>
Privkey 3b7134e3bc44a6993eb73af8f3e389a5188954d53fc4f30464e04c2b562db35e
*/

const (
	mnemonic = "hour luxury pizza relief material tail embrace motion foam book lyrics blur code mountain version pause mobile parrot glow worth happy ill ceiling almost"
)

func init() {
}

// Compare these
// 1. Cosmos SDK
// 2. Default Go package
// 3. https://github.com/dustinxie/ecc

func TestSignByKeyring(t *testing.T) {
	kr := keyring.NewInMemory()

	bip44 := hd.CreateHDPath(118, 0, 0)

	algo, err := keyring.NewSigningAlgoFromString("secp256k1", keyring.SigningAlgoList{hd.Secp256k1})
	if err != nil {
		panic(err)
	}

	keyInfo, err := kr.NewAccount("test", mnemonic, keyring.DefaultBIP39Passphrase, bip44.String(), algo)

	fmt.Println(keyInfo.GetAddress().String(), err)

	unsafeKr := keyring.NewUnsafe(kr)
	privKey, err := unsafeKr.UnsafeExportPrivKeyHex("test")

	msg := "Hello world"

	fmt.Println("Privkey", privKey)

	sig, pubKey, err := kr.Sign("test", []byte(msg))

	fmt.Println("Signature", hex.EncodeToString(sig))
	fmt.Println("Pub", pubKey.String())
	fmt.Println("Err", err)

	// With ext lib.
	digest := sha256.Sum256([]byte(msg))
	ecdsa.Sign(rand.Reader, nil, digest[:])
	ecc.P256k1()

}

func TestSignManually(t *testing.T) {
}
