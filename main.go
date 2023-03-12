package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"gonum.org/v1/gonum/mat"
	"math"
	"math/rand"
)

type encoding struct {
	index int
	i     int
	ijump int
	jjump int
	kjump int
	from  [2]int
	to    [2]int
	mask  *rlwe.Plaintext
}

func slicetomatrix(shape int, s []float64) [][]float64 {
	result := make([][]float64, shape)
	for temp := range result {
		result[temp] = make([]float64, shape)
	}
	for i := 0; i < shape; i++ {
		for j := 0; j < shape; j++ {
			result[i][j] = s[i*shape+j]
		}
	}
	return result
}

func encodewithindex(matrix [][]float64, index, shape int, encodings map[int]encoding, encoder ckks.Encoder, params ckks.Parameters) *rlwe.Plaintext {
	logslots := int(math.Log2(float64(shape))) * 3
	temp, _ := encodings[index]
	ijump, jjump, kjump := temp.ijump, temp.jjump, temp.kjump
	mat := encodeToVector(matrix, shape, ijump, jjump, kjump)
	plaintext := encoder.EncodeSlotsNew(mat, params.MaxLevel(), params.DefaultScale(), logslots)
	return plaintext
}

func decodewithindex(matrix *rlwe.Plaintext, index, shape int, encodings map[int]encoding, encoder ckks.Encoder) [][]float64 {
	logslots := int(math.Log2(float64(shape))) * 3
	temp, _ := encodings[index]
	ijump, jjump, _ := temp.ijump, temp.jjump, temp.kjump
	vector := encoder.DecodeSlots(matrix, logslots)
	mat := decodeToMatrix(vector, shape, ijump, jjump)
	return mat
}

func encodeToVector(matrix [][]float64, shape, ijump, jjump, kjump int) []float64 {
	res := make([]float64, shape*shape*shape)
	for i1 := 0; i1 < shape; i1++ {
		for j1 := 0; j1 < shape; j1++ {
			for k1 := 0; k1 < shape; k1++ {
				res[i1*ijump+j1*jjump+k1*kjump] = matrix[i1][j1]
			}
		}
	}
	return res
}

func decodeToMatrix(vector interface{}, i, ijump, jjump int) [][]float64 {
	res := make([][]float64, i)
	for temp := range res {
		res[temp] = make([]float64, i)
	}

	switch vector := vector.(type) {
	case []complex128:
		for i1 := 0; i1 < i; i1++ {
			for j1 := 0; j1 < i; j1++ {
				res[i1][j1] = real(vector[i1*ijump+j1*jjump])
			}
		}

	}

	return res
}

func getencodings(shape int, encoder ckks.Encoder, params ckks.Parameters) map[int]encoding {
	isquare := shape * shape
	logslots := int(math.Log2(float64(shape))) * 3

	var encodings = map[int]encoding{
		1: {index: 1, i: shape, ijump: shape, jjump: isquare, kjump: 1, from: [2]int{4, 6}, to: [2]int{3, 4}},
		2: {index: 2, i: shape, ijump: isquare, jjump: shape, kjump: 1, from: [2]int{3, 5}, to: [2]int{4, 3}},
		3: {index: 3, i: shape, ijump: isquare, jjump: 1, kjump: shape, from: [2]int{2, 4}, to: [2]int{5, 2}},
		4: {index: 4, i: shape, ijump: shape, jjump: 1, kjump: isquare, from: [2]int{1, 3}, to: [2]int{6, 1}},
		5: {index: 5, i: shape, ijump: 1, jjump: shape, kjump: isquare, from: [2]int{6, 2}, to: [2]int{1, 6}},
		6: {index: 6, i: shape, ijump: 1, jjump: isquare, kjump: shape, from: [2]int{5, 1}, to: [2]int{2, 5}},
	}

	for j := 1; j < 7; j++ {
		test, _ := encodings[j]
		ijump, jjump, _ := test.ijump, test.jjump, test.kjump
		mask := make([]float64, isquare*shape)
		for k := 0; k < isquare*shape; k++ {
			mask[k] = 0.0
		}
		for k := 0; k < shape; k++ {
			for l := 0; l < shape; l++ {
				mask[k*ijump+l*jjump] = 1.0
			}
		}
		test.mask = encoder.EncodeSlotsNew(mask, params.MaxLevel(), params.DefaultScale(), logslots)
		encodings[j] = test
	}

	return encodings
}

func multvectorizedmatrix_resultnotencoded(a, b *rlwe.Ciphertext, indexa, indexb int, encodings map[int]encoding, evaluator ckks.Evaluator) *rlwe.Ciphertext {
	valuea, ok := encodings[indexa]
	if ok != true {
		panic("Wrong index a")
	}
	if indexb != valuea.to[0] {
		panic("Wrong index b")
	}
	indexc := valuea.to[1]
	step := encodings[indexc].kjump

	n := int(math.Round(math.Log2(float64(2))))

	c := evaluator.MulRelinNew(a, b)
	evaluator.Rescale(c, rlwe.NewScale(1<<40), c)
	for i := 0; i < n; i++ {
		fmt.Println(step)
		d := evaluator.RotateNew(c, step)
		c = evaluator.AddNew(c, d)
		step *= 2
	}
	mask := encodings[indexc].mask

	result := evaluator.MulNew(c, mask)
	evaluator.Rescale(result, rlwe.NewScale(1<<40), result)
	return result
}

func multvectorizedmatrix_resultencoded(a, b *rlwe.Ciphertext, indexa, indexb, shape int, encodings map[int]encoding, evaluator ckks.Evaluator) *rlwe.Ciphertext {
	valuea, ok := encodings[indexa]
	if ok != true {
		panic("Wrong index a")
	}
	if indexb != valuea.to[0] {
		panic("Wrong index b")
	}
	indexc := valuea.to[1]
	step := encodings[indexc].kjump

	n := int(math.Round(math.Log2(float64(shape))))

	//fmt.Println("a", a.Level(), math.Log2(a.GetScale().Float64()))
	//fmt.Println("b", a.Level(), math.Log2(a.GetScale().Float64()))
	c := evaluator.MulRelinNew(a, b)
	//fmt.Println("1", c.Level(), math.Log2(c.GetScale().Float64()))
	evaluator.Rescale(c, rlwe.NewScale(1<<40), c)

	for i := 0; i < n; i++ {
		d := evaluator.RotateNew(c, step)
		c = evaluator.AddNew(c, d)
		step *= 2
	}
	mask := encodings[indexc].mask

	result := evaluator.MulNew(c, mask)
	//fmt.Println("2", result.Level(), math.Log2(result.GetScale().Float64()))
	evaluator.Rescale(result, rlwe.NewScale(1<<40), result)
	step = encodings[indexc].kjump
	for i := 0; i < n; i++ {
		result = evaluator.AddNew(evaluator.RotateNew(result, -step), result)
		step *= 2
	}
	//fmt.Println("3", result.Level(), math.Log2(result.GetScale().Float64()))
	return result
}

func getencodingslice(n int, index int, encodings map[int]encoding) (int, []int) {
	depth := 1
	l := n<<1 - 1
	for l>>1 > 0 {
		depth += 1
		l >>= 1
	}
	length := 1<<depth - 1
	s := make([]int, length)
	for i := 0; i < length; i++ {
		s[i] = 0
	}
	for i := 0; i < n; i++ {
		s[i] = 1
	}
	l = 1 << (depth - 1)
	start := l
	for i := 0; i < depth-1; i++ {
		for j := 0; j < l; j = j + 2 {
			if s[start-l+j] == 1 {
				s[start+j/2] = 1
			} else {
				s[start+j/2] = 0
			}
		}
		l >>= 1
		start += l
	}

	start = length - 1
	l = 1
	s[start] = index
	for i := 0; i < depth-1; i++ {
		for j := 0; j < l; j++ {
			if s[start+j] >= 1 {
				from := encodings[s[start+j]].from
				if s[start-(l<<1)+2*j+1] == 1 {
					s[start-(l<<1)+2*j] = from[0]
					s[start-(l<<1)+2*j+1] = from[1]
				} else {
					s[start-(l<<1)+2*j] = s[start+j]
				}
			}
		}
		l <<= 1
		start -= l
	}
	return depth, s
}

func consecutiveMul(s []int, cipherSlice []*rlwe.Ciphertext, shape int, encodings map[int]encoding, evaluator ckks.Evaluator) *rlwe.Ciphertext {
	length := len(s)

	for length > 1 {
		for i := 0; i < (length+1)/2; i++ {
			if 2*i+1 < length {
				//vec := encoder.DecodeSlots(decryptor.DecryptNew(cipherSlice[2*i]), 3)
				//fmt.Println(vec)
				//vec = encoder.DecodeSlots(decryptor.DecryptNew(cipherSlice[2*i+1]), 3)
				//fmt.Println(vec)
				cipherSlice[i] = multvectorizedmatrix_resultencoded(cipherSlice[2*i], cipherSlice[2*i+1], s[2*i], s[2*i+1], shape, encodings, evaluator)
				s[i] = encodings[s[2*i]].to[1]
			} else {
				cipherSlice[i] = cipherSlice[2*i]
				s[i] = s[2*i]
			}
			//fmt.Println(i, length)
			//vec := encoder.DecodeSlots(decryptor.DecryptNew(cipherSlice[i]), 3)
			//fmt.Println(vec)
			//fmt.Println(s)
			//fmt.Println("\n")
		}
		length = (length + 1) / 2
	}
	return cipherSlice[0]
}

func main() {
	//test := make([][]int, 64)

	//test := [][]float64{{1, 2}, {3, 4}}
	//result := encodeToVector(test, 2, 4, 2, 1)
	//res2 := decodeToMatrix(result, 2, 4, 2, 1)
	//fmt.Println(res2)
	data := make([]float64, 16)
	for i := range data {
		data[i] = rand.NormFloat64()
	}
	a := mat.NewDense(4, 4, data)
	for i := range data {
		data[i] = rand.NormFloat64()
	}
	b := mat.NewDense(4, 4, data)

	var c mat.Dense
	c.Mul(a, b)
	fc := mat.Formatted(&c, mat.Prefix("    "), mat.Squeeze())
	fmt.Printf("c = %v", fc)

	params, err := ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:         14,
			LogQ:         []int{55, 40, 40, 40, 40, 40, 40, 40},
			LogP:         []int{45, 45},
			LogSlots:     13,
			DefaultScale: 1 << 40,
		})
	//params, err := ckks.NewParametersFromLiteral(ckks.PN16QP1761)
	if err != nil {
		panic(err)
	}
	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlk := kgen.GenRelinearizationKey(sk, 1)

	//rots := make([]int, 7)
	//for i := 1; i < 8; i++ {
	//	rots[i-1] = (params.MaxSlots() >> 3) * i
	//}
	//rots = append(rots, []int{1, 2, 3, 4, 5, 6, 7, 8}...)
	rots := []int{1, 2, 3, 4, 5, 6, 7, -1, -2, -3, -4, -5, -6, -7}

	rotkey := kgen.GenRotationKeysForRotations(rots, false, sk)
	encryptor := ckks.NewEncryptor(params, sk)
	decryptor := ckks.NewDecryptor(params, sk)
	encoder := ckks.NewEncoder(params)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotkey})

	//values := []float64{2, 3, 4, 5}
	values2 := []float64{1, 0, 0, 1}
	//m1 := slicetomatrix(2, values)
	m2 := slicetomatrix(2, values2)
	encodings := getencodings(2, encoder, params)

	num := 6
	resultindex := 6
	_, encodingSlice := getencodingslice(num, resultindex, encodings)
	cipherslice := make([]*rlwe.Ciphertext, num)
	for i := 0; i < num; i++ {
		plain := encodewithindex(m2, encodingSlice[i], 2, encodings, encoder, params)
		cipherslice[i] = encryptor.EncryptNew(plain)
	}
	result := consecutiveMul(encodingSlice[0:num], cipherslice, 2, encodings, evaluator)
	//fmt.Println(encodingSlice)
	//return
	//plain1 := encodewithindex(m1, 1, 2, encodings, encoder, params)
	//plain2 := encodewithindex(m2, 3, 2, encodings, encoder, params)
	//cipher1 := encryptor.EncryptNew(plain1)
	//cipher2 := encryptor.EncryptNew(plain2)
	//
	//result := multvectorizedmatrix_resultnotencoded(cipher1, cipher2, 1, 3, encodings, evaluator)

	//plaintext := encoder.EncodeSlotsNew(values, params.MaxLevel(), params.DefaultScale(), 3)
	//ciphertext := encryptor.EncryptNew(plaintext)
	//fmt.Println(ciphertext.GetScale().Uint64() >> 30)

	//ciphertext2 := evaluator.MulNew(ciphertext, ciphertext)
	//evaluator.Rescale()
	//evaluator.Rescale(ciphertext2, rlwe.NewScale(1<<40), ciphertext2)
	//fmt.Println(ciphertext2.GetScale().Float64() / (1 << 35))
	//
	plaintext2 := decryptor.DecryptNew(result)

	//values22 := encoder.DecodeSlots(plaintext2, 3)

	fmt.Println(decodewithindex(plaintext2, resultindex, 2, encodings, encoder))
	fmt.Println(result.Level(), result.GetScale().Float64())
}
