// Decrypt

/*

        Author: Shikha Fadnavis
        Program : RSA key generation
        Date: 10/29/2017

*/

package main

import(
        "fmt"
        //crypt "crypto/rand"
        "math/big"
        "io/ioutil"
	"strings"
	"crypto/sha256"
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

func extendedEucledian(a *big.Int, b *big.Int) (*big.Int, *big.Int, *big.Int){

	d := big.NewInt(0)
	x := big.NewInt(0)
	y := big.NewInt(0)
	x1 := big.NewInt(0)
	x2 := big.NewInt(1)
	y1 := big.NewInt(1)
	y2 := big.NewInt(0)
	q := big.NewInt(0)
	r := big.NewInt(0)
	if b.Cmp(big.NewInt(0)) == 0{
		d.Set(a)
		x = big.NewInt(1)
		y = big.NewInt(0)
		return d,x,y
	}
		for b.Cmp(big.NewInt(0)) == 1{
			q.Div(a,b)
			r.Sub(a, big.NewInt(0).Mul(q,b))
			x.Sub(x2, big.NewInt(0).Mul(q,x1))
			y.Sub(y2, big.NewInt(0).Mul(q,y1))
			
			a.Set(b)
			b.Set(r)
			x2.Set(x1)
			x1.Set(x)
			y2.Set(y1)
			y1.Set(y)
			
		}
		


	d.Set(a)
	x.Set(x2)
	y.Set(y2)


	return d,x,y
}


func calculateRoots(mp *big.Int, mq *big.Int, yp *big.Int, yq *big.Int, p *big.Int, q *big.Int, n *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int){

	root1 := big.NewInt(0)
	root2 := big.NewInt(0)
	root3 := big.NewInt(0)
	root4 := big.NewInt(0)

	inter1 := big.NewInt(0)
	inter2 := big.NewInt(0)
	fmt.Println("p*mq is :", big.NewInt(0).Mul(p,mq))
	fmt.Println("yp*p is :", big.NewInt(0).Mul(yp,p))
	inter1.Mul(yp, p)
	inter1.Mul(inter1, mq)
	inter2.Mul(yq,q)
	inter2.Mul(inter2, mp)

	fmt.Println("inter1 before negative handling is: ", inter1)

	if inter1.Cmp(big.NewInt(0)) == -1{
		quo := big.NewInt(0)
		quo.Div(inter1,n)
		quo.Add(quo, big.NewInt(1))
		quo.Mul(quo,n)
		inter1.Add(inter1,quo)
	}

	if inter2.Cmp(big.NewInt(0)) == -1{
                quo := big.NewInt(0)
                quo.Div(inter2,n)
                quo.Add(quo, big.NewInt(1))
                quo.Mul(quo,n)
                inter2.Add(inter2,quo)
        }

	fmt.Println("intermediate1 is :", inter1)
	fmt.Println("intermediate2 is :", inter2)

	root1.Add(inter1, inter2)
	root1.Mod(root1,n)

	root3.Sub(inter1, inter2)
	root3.Mod(root3,n)

	root2.Sub(n, root1)
	root4.Sub(n, root3)

	return root1, root2, root3, root4

}

func rsaDecrypt(num *big.Int, N *big.Int, P *big.Int, Q *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int){

	// Calculate mp and mq
	mp := big.NewInt(0)
	mq := big.NewInt(0)

	mpExp := big.NewInt(0)
	mqExp := big.NewInt(0)

	mpExp.Add(P, big.NewInt(1))
	mpExp.Div(mpExp, big.NewInt(4))

	mqExp.Add(Q, big.NewInt(1))
        mqExp.Div(mqExp, big.NewInt(4))


	// Send to SqandMul algorithm

	mp = squareAndMultiplyWithMod(num, num, mpExp, P)
	mq = squareAndMultiplyWithMod(num, num, mqExp, Q)

	fmt.Println("mp is: ", mp)
	fmt.Println("mq is: ", mq)
	// Use Extended Eucledian Algo to find yp and yq

	yp := big.NewInt(0)
	yq := big.NewInt(0)
	PDup := big.NewInt(0)
	QDup := big.NewInt(0)

	PDup.Set(P)
	QDup.Set(Q)

	val1, val2, val3 := extendedEucledian(PDup, QDup)

	fmt.Println("Val1 is: ", val1)
	fmt.Println("Val2 is: ", val2)
	fmt.Println("Val3 is: ", val3)	

	yp.Set(val2)
	yq.Set(val3)

	fmt.Println("yp is: ", yp)
	fmt.Println("yq is: ", yq)

	root1, root2, root3, root4 := calculateRoots(mp, mq, yp, yq, P, Q, N)

	return root1, root2, root3, root4

}

func checkHash(num *big.Int) [32]byte{

	numStr := num.String()
	numHash := sha256.Sum256([]byte(numStr))

	return numHash
}

func main(){

	privateKeyFile := os.Args[1]
	cipherStr := os.Args[2]
	cipherStrLen := len(cipherStr)
	cipherHash := cipherStr[cipherStrLen-64:cipherStrLen]
	cipherOnly := cipherStr[0:cipherStrLen-64]

	cipher := big.NewInt(0)
	cipher.SetString(cipherOnly, 10)
	privKeyByte, readErr := ioutil.ReadFile(privateKeyFile)
	if readErr != nil{
		panic(readErr)
	}
	
	privKeyStr := strings.Split(string(privKeyByte), ",")
	recoveredN := privKeyStr[0]
	recoveredP := privKeyStr[1]
	recoveredQ := privKeyStr[2]
	
	recoveredNInt := big.NewInt(0)
	recoveredPInt := big.NewInt(0)
	recoveredQInt := big.NewInt(0)

	recoveredNInt.SetString(recoveredN,10)	
	recoveredPInt.SetString(recoveredP,10)
	recoveredQInt.SetString(recoveredQ,10)

	//fmt.Println("recovered P is: ", recoveredPInt)
	//fmt.Println("recovered Q is: ", recoveredQInt)
	
	root1, root2, root3, root4 := rsaDecrypt(cipher, recoveredNInt, recoveredPInt, recoveredQInt)
	//fmt.Println("Possible Plaintext values: ")
	
	fmt.Println("plaintext1 is: ", root1)
        fmt.Println("plaintext2 is: ", root2)
        fmt.Println("plaintext3 is: ", root3)
        fmt.Println("plaintext4 is: ", root4)

	root1Hash := checkHash(root1)
	root1HashStr := fmt.Sprintf("%x", root1Hash)
	root2Hash := checkHash(root2)
        root2HashStr := fmt.Sprintf("%x", root2Hash)
	root3Hash := checkHash(root3)
        root3HashStr := fmt.Sprintf("%x", root3Hash)
	root4Hash := checkHash(root4)
        root4HashStr := fmt.Sprintf("%x", root4Hash)

	if root1HashStr == cipherHash{
		fmt.Println("Plaintext found!: ", root1)
	}

	if root2HashStr == cipherHash{
                fmt.Println("Plaintext found!: ", root2)
        }
	
	if root3HashStr == cipherHash{
                fmt.Println("Plaintext found!: ", root3)
        }

	if root4HashStr == cipherHash{
                fmt.Println("Plaintext found!: ", root4)
        }


}
