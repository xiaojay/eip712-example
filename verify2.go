package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

func restoreSign(sign string) []byte {
	r := sign[4:]
	v := sign[2:4]
	l := len(r)

	//remove 0x Signature Type(the last two) and from v+r+s to r+s+v
	//https://github.com/0xProject/0x-monorepo/blob/08ae43aad3839831ee9e613be5e47cb9047d32a2/packages/order-utils/src/signature_utils.ts#L344
	r = r[:(l-2)] + v
	result, _ := hex.DecodeString(r)
	return result
}

func main() {
	userAddress := common.HexToAddress("0xf9593A9d7F735814B87D08e8D8aD624f58d53B10")
	//https://github.com/0xProject/0x-monorepo/blob/08ae43aad3839831ee9e613be5e47cb9047d32a2/packages/order-utils/src/signature_utils.ts#L295
	orderhash := "0x0ed657e750969e302e5b9345262892692a77b287b40630c896bb303a36f61617"
	signature := "0x1cb3d015b41413a2277e9b202e1991b5d223f491d538db56e3132e61b0e4e92b1844c5e02c7cd3d808d97f77e1302de64510a9f366bf62a600256bd1a125ff98cf03"

	data, _ := hex.DecodeString(orderhash[2:])
	hash := signHash(data)
	sign := restoreSign(signature)

	if len(sign) != 65 {
		fmt.Printf("invalid signature length: %d\n", len(sign))
	}

	if sign[64] != 27 && sign[64] != 28 {
		fmt.Printf("invalid recovery id: %d\n", sign[64])
	}
	sign[64] -= 27

	pubKeyRaw, err := crypto.Ecrecover(hash, sign)
	if err != nil {
		fmt.Printf("invalid signature: %s\n", err.Error())
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyRaw)
	if err != nil {
		fmt.Printf("%v", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	//fmt.Println("recover:", recoveredAddr.Hex())

	if !bytes.Equal(userAddress.Bytes(), recoveredAddr.Bytes()) {
		fmt.Println("addresses do not matcn")
	} else {
		fmt.Println("verified")
	}
}
