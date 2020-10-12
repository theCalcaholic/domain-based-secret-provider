package fn

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

var secret = os.Getenv("SECRET")
var trustedDomain = os.Getenv("TRUSTED_DOMAIN")

// GetKey Return encryption key on domain validation success
func GetKey(w http.ResponseWriter, r *http.Request) {

	fmt.Println(r.Header)

	if secret == "" {
		fmt.Println("WARN: Secret is empty")
	}

	if trustedDomain == "" {
		fmt.Println("ERROR: No trusted domain has been setup up (missing or empty environment variable TRUSTED_DOMAIN)!")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "INTERNAL SERVER ERROR")
		return
	}

	clientIP := ""
	if forwardedIPs, ok := r.Header["X-Forwarded-For"]; ok {
		clientIPs := forwardedIPs[len(forwardedIPs)-1]
		clientIPSplit := strings.Split(clientIPs, ",")
		clientIP = clientIPSplit[len(clientIPSplit)-1]
	} else {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	if clientIP == "" {
		fmt.Println("ERROR: An unexpected error occured while parsing the client IP.")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "INTERNAL SERVER ERROR")
		return
	}
	ips, err := net.LookupIP(trustedDomain)

	if err != nil {
		fmt.Print("ERROR: Failed to lookup domain!")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "INTERNAL SERVER ERROR")
		return
	}

	for _, ip := range ips {
		if ip.String() == clientIP {
			fmt.Printf("Validation successful: Domain IP (%s) matches Client IP(%s)\n", ip, clientIP)
			fmt.Fprint(w, secret)
			return
		}
	}

	fmt.Printf("Auhtorization failed for Client (%s)\n", clientIP)
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, "Domain validation failed!")

}
