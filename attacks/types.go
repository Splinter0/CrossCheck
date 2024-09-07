package attacks

import (
	"log"
	"regexp"
	"strings"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
)

type AttackType struct {
	Name      string
	Regex     string // Regex matching the desired deep link
	Prefix    string // Deep link prefix needed when rebuilding deep links
	ReturnArg string // Some protocols embed a "return" query parameter, if you want to play with that, set the return arg to the name of that parameter
}

func RegexExtract(content, pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		log.Println(err)
	}

	return re.FindString(content)
}

// Extracts the deep link using attack details
func (at *AttackType) Extract(content string) string {
	link := RegexExtract(content, at.Regex)

	if link != "" && !strings.HasPrefix(link, at.Prefix) {
		link = at.Prefix + link
	}

	return link
}

// Modifies the return argument when provided
func (at *AttackType) ModifyReturn(url, replace string) string {
	if at.ReturnArg == "" {
		return url
	}
	s := strings.Split(url, "&"+at.ReturnArg)
	return s[0] + "&" + at.ReturnArg + "=" + replace
}

type AttackResult struct {
	Id           string
	DeepLink     string
	ExfilChannel chan string
}

func NewAttackResult(deepLink string) AttackResult {
	return AttackResult{
		Id:           uuid.New().String(),
		DeepLink:     deepLink,
		ExfilChannel: make(chan string, 1),
	}
}

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

func (a Attack) Result(deepLink string) AttackResult {
	return NewAttackResult(a.Type.ModifyReturn(deepLink, a.RedirectURL))
}
