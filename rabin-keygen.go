/*

	Author: Shikha Fadnavis
	Program : Rabin key generation
	Date: 10/29/2017

*/

package main

import(
	"fmt"
	crypt "crypto/rand"
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

func squareAndMultiply(num *big.Int, exp *big.Int) (*big.Int){

	var i int 
	var res *big.Int
	//Start square and multiply
	binExp := fmt.Sprintf("%b", exp)
	if exp == big.NewInt(1){
		return num
	}
	for i = 1; i < len(binExp); i++{
		if binExp[i] == 49{
			//sq and mul
			res.Mul(res,res)
			res.Mul(res,num)
			
		}else{
			//only sq
			res.Mul(res,res)

		}
	}

	return res

}


func millerTest(num *big.Int, factor *big.Int, pow *big.Int) bool{


	b := big.NewInt(0)
	mulRes := big.NewInt(0)
	var i *big.Int

	randNumMiller := big.NewInt(0)
	randNumByteMiller := make([]byte,64)
        crypt.Read(randNumByteMiller)
        randNumMiller.SetBytes(randNumByteMiller)

	b = squareAndMultiplyWithMod(randNumMiller, randNumMiller, factor, num)

	if b.Cmp(big.NewInt(1)) == 0 || b.Cmp(big.NewInt(0).Sub(num,big.NewInt(1))) == 0{
	
		return true
	}

	for i = big.NewInt(0); i.Cmp(pow) == -1; i.Add(i,big.NewInt(1)){
        	mulRes.Mul(b,b)
		b.Mod(mulRes, num)
                if b.Cmp(big.NewInt(1)) == 0{
			
			return false
		}
		if b.Cmp(big.NewInt(0).Sub(num,big.NewInt(1))) == 0{
			
			return true
		}

        }// end of squaring for
 
				

	return false	

}

func millerRabinPrime(num *big.Int) bool{

	var factor *big.Int 
	

	a := big.NewInt(0)	
	a.Sub(num,big.NewInt(1))
	k := big.NewInt(0) 
	modulus := big.NewInt(0)
	for true{
		a.Div(a,big.NewInt(2)) 
		modulus.Mod(a,big.NewInt(2))
		if modulus.Cmp(big.NewInt(0)) == 0{
			k.Add(k,big.NewInt(1))
		}else{
			break
		}
	}

	factor = big.NewInt(0)
	factor.Mul(a,big.NewInt(2))
	pow := big.NewInt(0)
	pow.Sub(k,big.NewInt(0)) 

	for j := 0; j < 5; j++{
	
		//Call miller test
		if millerTest(num, factor, pow) == false{
			return false
		}
	
	}// end of randomnums for

	return true

} // end of func


func randGenerate() *big.Int{
	
	randNum := big.NewInt(0)
	
	for true{
		randNumByte := make([]byte,64)
		crypt.Read(randNumByte)
		randNum.SetBytes(randNumByte)
//		fmt.Println("random number chosen is: ", randNum)
		operation := big.NewInt(0)
		operation.Mod(randNum, big.NewInt(2))
		if operation.Cmp(big.NewInt(0)) == 0{
//			fmt.Println("Composite Number")
			//generate random again
		}else{
			primeRes := millerRabinPrime(randNum)
			if primeRes == true{
//				fmt.Println("\n Prime number")
				break
			}else{
//				fmt.Println("\n Composite Number")
			}
		}
	}

	return randNum

}


func writePubKey(N *big.Int, filename string){
	NStr := N.String()
	openB := "("
	closeB := ")"
	NStr = openB + NStr + closeB
	eFileByte := []byte(NStr)
	writeErr := ioutil.WriteFile(filename,eFileByte, 0644)
	if writeErr != nil{
		panic(writeErr)
	}	
}

func writePrivKey(N *big.Int, p *big.Int, q *big.Int, filename string){
	NStr := N.String()
	openB := "("
        closeB := ")"
	comma := ","
	pStr := p.String()
	qStr := q.String()

	dFileStr := openB + NStr + comma + pStr + comma + qStr + closeB
	dFileByte := []byte(dFileStr)
	writeErr := ioutil.WriteFile(filename, dFileByte, 0644)
	if writeErr != nil{
		panic(writeErr)
	}	
	


}

func main(){

	modulus := big.NewInt(0)

	// Generate "p" and "q"
	prime1 := big.NewInt(0)
	prime2 := big.NewInt(0)

	prime1Mod := big.NewInt(0)
        prime2Mod := big.NewInt(0)

	for true{
		prime1 = randGenerate()
		prime1Mod.Mod(prime1, big.NewInt(4))

		if prime1Mod.Cmp(big.NewInt(3)) == 0{
			break
		}
	}

	for true{
                prime2 = randGenerate()
                prime2Mod.Mod(prime2, big.NewInt(4))

                if prime2Mod.Cmp(big.NewInt(3)) == 0{
                        break
                }
        }

	
	// Calculate "N"

//	prime1 := big.NewInt(7)
//	prime2 := big.NewInt(11)	
	modulus.Mul(prime1, prime2)



//	fmt.Println("Prime 1 is: ", prime1)
//        fmt.Println("Prime 2 is: ", prime2)
//        fmt.Println("Public Modulus is: ", modulus)


	// Write keys to respective files
	
	writePubKey(modulus, os.Args[1])

	writePrivKey(modulus, prime1, prime2, os.Args[2])

	

}



