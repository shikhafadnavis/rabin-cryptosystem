/*

        Author: Shikha Fadnavis
        Program : Rabin Encryption
        Date: 10/29/2017

*/

package main

import(
        "fmt"
        "math/big"
        "io/ioutil"
	"os"
	"crypto/sha256"
)

func squareAndMultiplyWithMod(a *big.Int, a2 *big.Int, b *big.Int, c *big.Int) (*big.Int){

	var i int 
	var startVal, res, someRes, preRes *big.Int

	binExp := fmt.Sprintf("%b", b)
	if b == big.NewInt(1){
		return a
	}

	// Retain original value
	startVal = big.NewInt(0)
	startVal.Mod(a,c)

	res = big.NewInt(0)
	res.Mod(a2,c)

	for i = 1; i < len(binExp); i++{	
		// Square regardless
		someRes = big.NewInt(0)
		someRes.Mul(res, res)
		res.Mod(someRes, c)

		if binExp[i] == 49{
			preRes = big.NewInt(0)
			preRes.Mul(res, startVal)
			res.Mod(preRes,c)			
		}

	}

	return res	
		


}

func rabinEncrypt(num *big.Int, N *big.Int, plaintextStr string) (*big.Int, string){

	res := squareAndMultiplyWithMod(num, num, big.NewInt(2), N)
	plainHash := sha256.Sum256([]byte(plaintextStr))
        plainHashHex := fmt.Sprintf("%x",plainHash)

	return res, plainHashHex

}

func main(){

	publicKeyFile := os.Args[1]
	plaintextStr := os.Args[2]
	plaintext := big.NewInt(0)
	plaintext.SetString(plaintextStr,10)
	pubKeyByte, readErr := ioutil.ReadFile(publicKeyFile)
	if readErr != nil{
		panic(readErr)
	}
	
	pubKeyStr := string(pubKeyByte)
	pubKeyStr = pubKeyStr[1: len(pubKeyStr)-1]


	recoveredNInt := big.NewInt(0)
	recoveredNInt.SetString(pubKeyStr,10)	
 
	cipher, plainHashStr := rabinEncrypt(plaintext, recoveredNInt, plaintextStr)
	
	cipherAppend := cipher.String() + plainHashStr

	fmt.Println("Encrypted text: ", cipherAppend)
	
	

}
