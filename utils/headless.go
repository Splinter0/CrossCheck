package utils

import "github.com/chromedp/cdproto/fetch"

func GetHeadersForContinueRequest(headers map[string]interface{}) (entries []*fetch.HeaderEntry) {
	for k, v := range headers {
		entries = append(
			entries,
			&fetch.HeaderEntry{
				Name:  k,
				Value: v.(string),
			},
		)
	}
	return
}
