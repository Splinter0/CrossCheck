package utils

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

func FidoToCbor(fido string) (map[int]interface{}, error) {
	result := make(map[int]interface{})
	var decoded []byte

	for i := 0; i < len(fido); i += 17 {
		end := i + 17
		if end > len(fido) {
			end = len(fido)
		}

		chunk := fido[i:end]
		var n int
		switch len(chunk) {
		case 3:
			n = 1
		case 5:
			n = 2
		case 8:
			n = 3
		case 10:
			n = 4
		case 13:
			n = 5
		case 15:
			n = 6
		case 17:
			n = 7
		default:
			return nil, errors.New("invalid chunk length")
		}

		num, err := strconv.ParseUint(chunk, 10, 64)
		if err != nil {
			return nil, err
		}

		bytes := make([]byte, 8)
		for j := 0; j < 8; j++ {
			bytes[j] = byte(num >> (8 * j))
		}

		decoded = append(decoded, bytes[:n]...)
	}

	err := cbor.Unmarshal(decoded, &result)
	fmt.Println(result)
	return result, err
}

func CborToFido(cborData map[int]interface{}) (string, error) {
	encoded, err := cbor.Marshal(cborData)
	if err != nil {
		return "", err
	}

	return BytesToBase10String(encoded), nil
}

func BytesToBase10String(byteData []byte) string {
	var result strings.Builder
	chunkLengths := map[int]int{
		1: 3,
		2: 5,
		3: 8,
		4: 10,
		5: 13,
		6: 15,
		7: 17,
	}

	i := 0
	for i < len(byteData) {
		n := 7
		if len(byteData)-i < 7 {
			n = len(byteData) - i
		}

		num := uint64(0)
		for j := 0; j < n; j++ {
			num |= uint64(byteData[i+j]) << (8 * j)
		}

		chunkLength := chunkLengths[n]
		result.WriteString(fmt.Sprintf("%0*d", chunkLength, num))

		i += n
	}

	return result.String()
}

func FidoLinkToCbor(fido string) (map[int]interface{}, error) {
	s := strings.Split(fido, "FIDO:/")
	return FidoToCbor(s[1])
}

func MakeDiscoverable(fido string) (string, error) {
	cborData, err := FidoLinkToCbor(fido)
	log.Println(cborData)
	if err != nil {
		return "", err
	}

	cborData[6] = false
	n, err := CborToFido(cborData)
	return "FIDO:/" + n, err
}
