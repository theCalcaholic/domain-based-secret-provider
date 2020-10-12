package main

import (
	"net/http"
	"os"

	"github.com/thecalcaholic/domain-validation-secret-provider/fn"
)

func main() {

	http.HandleFunc("/", fn.GetKey)

	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "80"
	}

	http.ListenAndServe(":"+port, nil)

}
