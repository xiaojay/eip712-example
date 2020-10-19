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
	signature, _ := hex.DecodeString("6dfdd3e10e4e9163d31ccf20952023bc5c71aca1534b80541c6ab46d0ff884590d07259d1468d15a15de33dbcf44a4ece90e430d6dd9361e5364e94abd1b936e1c")
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
