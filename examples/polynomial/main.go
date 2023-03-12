package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"time"
)

func calculatepower(power int, s map[int]*rlwe.Ciphertext, evaluator ckks.Evaluator) *rlwe.Ciphertext {
	value, ok := s[power]
	if ok {
		return value
	} else {
		fmt.Println(power)
		i1 := power >> 1
		i2 := power - i1
		value1 := calculatepower(i2, s, evaluator)
		value2 := calculatepower(i1, s, evaluator)
		value := evaluator.MulRelinNew(value1, value2)
		s[power] = value
		return value
	}
}

func calculatePoly(coefficient []float64, ciphertext *rlwe.Ciphertext, evaluator ckks.Evaluator, ctout *rlwe.Ciphertext) {
	l := len(coefficient)
	storage := make(map[int]*rlwe.Ciphertext, l)
	//ciphers := make([]*rlwe.Ciphertext, l)
	storage[1] = ciphertext.CopyNew()
	for i := 1; i < l; i++ {
		if coefficient[i] != 0 {
			newciphertext := calculatepower(i, storage, evaluator)
			cipherwithcoeff := evaluator.MultByConstNew(newciphertext, coefficient[i])
			evaluator.Add(ctout, cipherwithcoeff, ctout)
		}
	}
	evaluator.AddConst(ctout, coefficient[0], ctout)
}

func main() {
	params, err := ckks.NewParametersFromLiteral(ckks.PN14QP438)
	if err != nil {
		panic(err)
	}
	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlk := kgen.GenRelinearizationKey(sk, 1)

	//rots := []int{2}
	//rotkey := kgen.GenRotationKeysForRotations(rots, false, sk)
	encryptor := ckks.NewEncryptor(params, sk)
	decryptor := ckks.NewDecryptor(params, sk)
	encoder := ckks.NewEncoder(params)
	//evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotkey})
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})

	coefficient := []float64{2, 3, 4, 5, 6, 7, 8, 9}
	values := []float64{3, 4}
	plaintext := encoder.EncodeSlotsNew(values, params.MaxLevel(), params.DefaultScale(), 3)
	ciphertext := encryptor.EncryptNew(plaintext)

	//fmt.Println(ciphertext.GetScale().Uint64() >> 30)
	ciphertext2 := ckks.NewCiphertext(params, 1, params.MaxLevel())
	t1 := time.Now()
	calculatePoly(coefficient, ciphertext, evaluator, ciphertext2)
	//t2 := time.Now()
	interval := time.Since(t1)
	fmt.Println(interval)
	//evaluator.Rescale()
	//evaluator.Rescale(ciphertext2, rlwe.NewScale(1<<40), ciphertext2)
	fmt.Println(ciphertext2.GetScale().Float64() / (1 << 35))

	plaintext2 := decryptor.DecryptNew(ciphertext2)

	values2 := encoder.DecodeSlots(plaintext2, 3)

	fmt.Println(values2)
}
