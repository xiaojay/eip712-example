package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core"
)

func main() {
	data, _ := ioutil.ReadFile("./order.json")
	var typedData core.TypedData
	err := json.Unmarshal(data, &typedData)
	if err != nil {
		fmt.Println(err)
	}
	typedDataHash, _ := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	domainSeparator, _ := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	hash := crypto.Keccak256Hash(rawData)

	//fmt.Printf("hash is %v(%T)\n", hash, hash)
	fmt.Println("hash is", hash.Hex())

	userAddress := common.HexToAddress("0xf9593A9d7F735814B87D08e8D8aD624f58d53B10")
	signature, _ := hex.DecodeString("a9a3e5f72b48651b735d0908f1f240b06eafe7166dbe6b4fc8b57d8b8515ef555fe4b124c2b50d6907423426ec46bc12c5956942dcfd01e02d70912c87a389c41b")
	if len(signature) != 65 {
		fmt.Printf("invalid signature length: %d", len(signature))
	}

	if signature[64] != 27 && signature[64] != 28 {
		fmt.Printf("invalid recovery id: %d", signature[64])
	}
	signature[64] -= 27

	pubKeyRaw, err := crypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		fmt.Printf("invalid signature: %s", err.Error())
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyRaw)
	if err != nil {
		fmt.Printf("%v", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	fmt.Println("recover:", recoveredAddr.Hex())
	fmt.Println("user:", userAddress.Hex())

	if !bytes.Equal(userAddress.Bytes(), recoveredAddr.Bytes()) {
		fmt.Println("addresses do not matcn")
	}
}
