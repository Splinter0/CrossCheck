package main

import (
	"github.com/Splinter0/CrossCheck/attacks"
	httphandler "github.com/Splinter0/CrossCheck/http-handler"
)

func main() {
	httphandler.LaunchAttacks(attacks.DemoAbleAttacks(), attacks.DemoQRProxyAttacks(), attacks.PasskeyProxyAttacks())
}
