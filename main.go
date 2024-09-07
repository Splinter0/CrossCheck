package main

import (
	"github.com/Splinter0/Fixer/attacks"
	httphandler "github.com/Splinter0/Fixer/http-handler"
)

func main() {
	httphandler.LaunchAttacks(attacks.DemoAbleAttacks(), attacks.DemoQRProxyAttacks())
}
