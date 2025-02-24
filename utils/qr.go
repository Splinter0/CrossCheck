package utils

import (
	"bytes"
	"image"
	"image/png"
	_ "image/png"
	"io/ioutil"
	"log"
	"os"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

func DecodeQR(imageData []byte) string {
	img, _, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		log.Println("Failed to read image for QR code", err.Error())
		return ""
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		log.Println("Failed to create bitmap for image", err.Error())
		return ""
	}

	reader := qrcode.NewQRCodeReader()
	result, err := reader.Decode(bmp, nil)
	if err != nil {
		log.Println("Failed to read QR data", err.Error())
		return ""
	}
	return result.GetText()
}

func CreateQR(qrData string) {
	writer := qrcode.NewQRCodeWriter()
	img, err := writer.EncodeWithoutHint(qrData, gozxing.BarcodeFormat_QR_CODE, 500, 500)
	if err != nil {
		log.Println("Error writing QR code", err.Error())
	}
	file, _ := os.Create("qr.png")
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		log.Println("Error saving QR code", err.Error())
	}
}

func DecodeQRCodeFromFile(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed reading qr code from file: %s", err)
		return ""
	}

	return DecodeQR(data)
}
