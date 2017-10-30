/*

        Author: Shikha Fadnavis
        Program : Rabin Encryption
        Date: 10/29/2017

*/

package main

import(
        "fmt"
        //crypt "crypto/rand"
        "math/big"
        "io/ioutil"
	"os"
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

func rabinEncrypt(num *big.Int, N *big.Int) *big.Int{

	res := squareAndMultiplyWithMod(num, num, big.NewInt(2), N)
	return res

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


	recoveredNInt := big.NewInt(0)
	recoveredNInt.SetString(pubKeyStr,10)	
 
	cipher := rabinEncrypt(plaintext, recoveredNInt)
	fmt.Println("Encrypted text: ", cipher)
	

}
