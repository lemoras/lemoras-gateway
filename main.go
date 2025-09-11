package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cookieSuffix        = "_token"
	csrfCookieSuffix    = "_csrf_token"
	accountTokenCookie  = "account_token"
	tokenLength         = 32
	tokenExpiry         = 20 * time.Minute
	tokenExtendPeriod   = 15 * time.Minute
	tokenRenewThresh    = 10 * time.Minute
	normalRateLimit     = 50
	validationRateLimit = 350
	rateLimitWindow     = 60 * time.Second
	maxUploadSize       = 10 << 20 // 10 MB
)

var (
	originsMu      sync.RWMutex
	allowedOrigins = []string{
		"http://dev.local",
		"https://dev.local",
		"http://account.dev.local",
		"https://account.dev.local",
		"http://api.dev.local",
		"https://api.dev.local",
		"http://notes.dev.local",
		"https://notes.dev.local",
	}
	trustedProxies  = []string{"127.0.0.1", "10.0.0.0/8"}
	remoteConfigURL = "https://dev.local/system/local-config.json"
)

// --- Token & Limiter kodları (aynı) ---
func generateSecureToken(token string) (string, error) {
	secret := os.Getenv("RATE_SECRET_KEY")
	if secret == "" {
		return "", errors.New("RATE_SECRET_KEY not set")
	}
	randomPart := make([]byte, tokenLength)
	if _, err := rand.Read(randomPart); err != nil {
		return "", err
	}
	timestamp := time.Now().UnixNano()
	data := fmt.Sprintf("%s|%x|%d", token, randomPart, timestamp)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	signature := fmt.Sprintf("%x", h.Sum(nil))
	tokenStr := fmt.Sprintf("%s|%s", data, signature)
	return base64.RawURLEncoding.EncodeToString([]byte(tokenStr)), nil
}

func validateToken(tokenStr string) (string, error) {
	secret := os.Getenv("RATE_SECRET_KEY")
	if secret == "" {
		return "", errors.New("RATE_SECRET_KEY not set")
	}
	dataBytes, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(dataBytes), "|")
	if len(parts) != 4 {
		return "", errors.New("invalid token format")
	}
	userID := parts[0]
	random := parts[1]
	timestampStr := parts[2]
	signature := parts[3]

	data := fmt.Sprintf("%s|%s|%s", userID, random, timestampStr)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	expected := fmt.Sprintf("%x", h.Sum(nil))
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return "", errors.New("invalid token signature")
	}

	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", errors.New("invalid timestamp")
	}
	if time.Since(time.Unix(0, ts)) > tokenExpiry {
		return "", errors.New("token expired")
	}
	return userID, nil
}

type userData struct {
	mu         sync.Mutex
	timestamps []time.Time
}

type SlidingWindowLimiter struct {
	users sync.Map
}

func NewSlidingWindowLimiter() *SlidingWindowLimiter {
	return &SlidingWindowLimiter{}
}

func (l *SlidingWindowLimiter) AllowRequest(key string, maxReq int) bool {
	now := time.Now()
	val, _ := l.users.LoadOrStore(key, &userData{})
	user := val.(*userData)

	user.mu.Lock()
	defer user.mu.Unlock()

	validAfter := now.Add(-rateLimitWindow)
	newTimestamps := user.timestamps[:0]
	for _, t := range user.timestamps {
		if t.After(validAfter) {
			newTimestamps = append(newTimestamps, t)
		}
	}
	user.timestamps = newTimestamps

	if len(user.timestamps) >= maxReq {
		return false
	}

	user.timestamps = append(user.timestamps, now)
	return true
}

func (l *SlidingWindowLimiter) Cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			now := time.Now()
			l.users.Range(func(key, val interface{}) bool {
				user := val.(*userData)
				user.mu.Lock()
				validAfter := now.Add(-rateLimitWindow)
				newTimestamps := user.timestamps[:0]
				for _, t := range user.timestamps {
					if t.After(validAfter) {
						newTimestamps = append(newTimestamps, t)
					}
				}
				user.timestamps = newTimestamps
				if len(user.timestamps) == 0 {
					l.users.Delete(key)
				}
				user.mu.Unlock()
				return true
			})
		}
	}()
}

// --- IP ve CSRF ---
func isTrustedProxy(ip string) bool {
	for _, proxy := range trustedProxies {
		if strings.HasPrefix(ip, proxy) {
			return true
		}
	}
	return false
}

func getIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(parts[0])
		if isTrustedProxy(r.RemoteAddr) {
			return clientIP
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func validateCSRF(r *http.Request) error {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		return nil
	}
	csrfCookie, err := r.Cookie(csrfCookieSuffix)
	if err != nil {
		return errors.New("CSRF cookie missing")
	}
	csrfHeader := r.Header.Get("X-CSRF-Token")
	if csrfHeader == "" {
		return errors.New("CSRF token header missing")
	}
	if csrfCookie.Value != csrfHeader {
		return errors.New("CSRF token mismatch")
	}
	return nil
}

func getSubdomain(host, mainDomain string) string {
	host = strings.ToLower(host)
	if strings.HasSuffix(host, mainDomain) {
		trimmed := strings.TrimSuffix(host, mainDomain)
		trimmed = strings.TrimSuffix(trimmed, ".")
		if trimmed == "" {
			return ""
		}
		return trimmed
	}
	return ""
}

func setCookieHeader(name, value, domain string, expiry time.Duration) string {
	return fmt.Sprintf("%s=%s; Path=/; Domain=%s; HttpOnly; Secure; Max-Age=%d; SameSite=None",
		name, value, domain, int(expiry.Seconds()))
}

func renewAllValidSubdomainCookies(w http.ResponseWriter, r *http.Request, mainDomain string) {
	for _, cookie := range r.Cookies() {
		if strings.HasSuffix(cookie.Name, cookieSuffix) {
			if _, err := validateToken(cookie.Value); err != nil {
				continue
			}
			expires := time.Now().Add(tokenExtendPeriod)
			http.SetCookie(w, &http.Cookie{
				Name:     cookie.Name,
				Value:    cookie.Value,
				Path:     "/",
				Domain:   "." + mainDomain,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteNoneMode,
				Expires:  expires,
				MaxAge:   int(tokenExtendPeriod.Seconds()),
			})
		}
	}
}

// type loggingRoundTripper struct {
// 	rt http.RoundTripper
// }

// func (lrt *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
// 	fmt.Println(">>> Outgoing request to backend:", req.URL.String())
// 	for name, values := range req.Header {
// 		for _, v := range values {
// 			fmt.Printf("Header: %s = %s\n", name, v)
// 		}
// 	}
// 	return lrt.rt.RoundTrip(req)
// }

// --- Reverse Proxy ---
func newReverseProxy(targetEnv string) *httputil.ReverseProxy {
	targetURL := os.Getenv(targetEnv)
	if targetURL == "" {
		log.Fatalf("%s environment variable is not set", targetEnv)
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Invalid %s: %v", targetEnv, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		mainDomain := os.Getenv("MAIN_DOMAIN")
		cookieName := accountTokenCookie
		hostURL := req.Header.Get("X-Original-Host")
		subdomain := getSubdomain(hostURL, mainDomain)
		if subdomain != "" {
			cookieName = subdomain + cookieSuffix
		}
		fmt.Println("cookieName: " + cookieName)
		if cookie, err := req.Cookie(cookieName); err == nil {
			token := cookie.Value
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
		}
	}

	// proxy.Transport = &loggingRoundTripper{rt: http.DefaultTransport}

	proxy.ModifyResponse = func(resp *http.Response) error {

		resp.Header.Del("Access-Control-Allow-Origin")
		resp.Header.Del("Access-Control-Allow-Credentials")
		resp.Header.Del("Access-Control-Allow-Headers")
		resp.Header.Del("Access-Control-Allow-Methods")

		if strings.Contains(resp.Request.URL.Path, "/security/authenticate") {
			bodyCopy, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()
			resp.Body = io.NopCloser(strings.NewReader(string(bodyCopy)))

			var parsed map[string]interface{}
			if err := json.Unmarshal(bodyCopy, &parsed); err != nil {
				log.Printf("Error parsing authenticate response: %v", err)
				return nil
			}

			if success, ok := parsed["status"].(bool); ok && success {
				if account, ok := parsed["account"].(map[string]interface{}); ok {
					if token, ok := account["token"].(string); ok && token != "" {
						mainDomain := os.Getenv("MAIN_DOMAIN")
						hostURL := resp.Header.Get("X-Original-Host")
						subdomain := getSubdomain(hostURL, mainDomain)
						if subdomain != "" {
							subToken, err := generateSecureToken(token)
							if err != nil {
								log.Printf("Error generating subdomain token: %v", err)
								return nil
							}
							resp.Header.Add("Set-Cookie", setCookieHeader(subdomain+cookieSuffix, subToken, "."+mainDomain, tokenExpiry))
						}
						resp.Header.Add("Set-Cookie", setCookieHeader(accountTokenCookie, token, "."+mainDomain, tokenExpiry))
					}
				}
			}
		}
		return nil
	}

	return proxy
}

// --- Dynamic CORS ---
func updateAllowedOrigins() error {
	resp, err := http.Get(remoteConfigURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch config: %s", resp.Status)
	}

	var data []struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	newOrigins := make([]string, 0)
	seen := make(map[string]struct{})
	for _, d := range data {
		for _, o := range d.Domains {
			o = strings.TrimSpace(o)
			if o != "" {
				if _, ok := seen[o]; !ok {
					seen[o] = struct{}{}
					newOrigins = append(newOrigins, "https://"+o)
				}
			}
		}
	}

	originsMu.Lock()
	allowedOrigins = newOrigins
	originsMu.Unlock()
	return nil
}

func isOriginAllowed(origin string) bool {
	originsMu.RLock()
	defer originsMu.RUnlock()
	for _, o := range allowedOrigins {
		if o == origin {
			return true
		}
	}
	return false
}

// --- Main ---
func main() {
	mainDomain := os.Getenv("MAIN_DOMAIN")
	if mainDomain == "" {
		log.Fatal("MAIN_DOMAIN environment variable is not set")
	}

	// Initialize allowedOrigins
	if err := updateAllowedOrigins(); err != nil {
		log.Printf("Failed to initialize allowedOrigins: %v", err)
	}

	limiter := NewSlidingWindowLimiter()
	limiter.Cleanup(5 * time.Minute)

	securityProxy := newReverseProxy("SECURITY_TARGET_URL")
	systemProxy := newReverseProxy("SYSTEM_TARGET_URL")
	serviceProxy := newReverseProxy("SERVICE_TARGET_URL")
	fileProxy := newReverseProxy("FILE_TARGET_URL")

	// apacheURL, _ := url.Parse("https://apache.otherdomain.local")
	// apacheProxy := httputil.NewSingleHostReverseProxy(apacheURL)

	http.HandleFunc("/refresh-origins", func(w http.ResponseWriter, r *http.Request) {
		if err := updateAllowedOrigins(); err != nil {
			http.Error(w, "Failed to refresh allowed origins: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Allowed origins refreshed"))
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// --- Rate limit ---
		ip := getIP(r)
		key := ip
		if cookie, err := r.Cookie(accountTokenCookie); err == nil {
			key = ip + "_" + cookie.Value
		}

		maxReq := normalRateLimit
		if strings.Contains(r.URL.Path, "security/validation") {
			maxReq = validationRateLimit
		}

		if !limiter.AllowRequest(key, maxReq) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// --- CORS ---
		origin := r.Header.Get("Origin")
		if origin != "" {
			if isOriginAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
				w.Header().Set("Access-Control-Allow-Credentials", "true")

				if r.Header.Get("X-Original-Host") == "" {
					xOrgin := origin
					xOrgin = strings.TrimPrefix(xOrgin, "http://")
					xOrgin = strings.TrimPrefix(xOrgin, "https://")
					r.Header.Set("X-Original-Host", xOrgin)
				}

			} else {
				http.Error(w, "CORS origin not allowed", http.StatusForbidden)
				return
			}
		}

		// --- Security headers ---
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// --- Max upload ---
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			contentType := r.Header.Get("Content-Type")
			mediatype, _, err := mime.ParseMediaType(contentType)
			if err == nil && mediatype == "multipart/form-data" {
				r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
			}
		}

		// --- Cookie renewal ---
		subdomain := getSubdomain(r.Header.Get("X-Original-Host"), mainDomain)
		cookieName := subdomain + cookieSuffix
		if cookieName != "" {
			if cookie, err := r.Cookie(cookieName); err == nil {
				if _, err := validateToken(cookie.Value); err == nil {
					if time.Until(cookie.Expires) < tokenRenewThresh {
						renewAllValidSubdomainCookies(w, r, mainDomain)
					}
				}
			}
		}

		// CSRF
		// if err := validateCSRF(r); err != nil {
		// 	http.Error(w, "CSRF validation failed: "+err.Error(), http.StatusForbidden)
		// 	return
		// }

		// --- /api prefix stripping ---
		path := r.URL.Path
		// if strings.HasPrefix(path, "/api/") {
		// 	path = strings.TrimPrefix(path, "/api")
		// 	r.URL.Path = path

		switch {
		case strings.HasPrefix(path, "/security"):
			securityProxy.ServeHTTP(w, r)
		case strings.HasPrefix(path, "/system/file"):
			fileProxy.ServeHTTP(w, r)
		case strings.HasPrefix(path, "/system"):
			systemProxy.ServeHTTP(w, r)
		default:
			serviceProxy.ServeHTTP(w, r)
		}
		// } else {
		// 	// /api prefix yok → farklı domain'e yönlendir
		// 	apacheProxy.ServeHTTP(w, r)
		// }
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}
	log.Printf("Server listening on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
