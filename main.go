package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
)

type contextKey int

var ContextKey = contextKey(0)

type ClientHello struct {
	info *tls.ClientHelloInfo
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		tlsState := r.TLS
		if tlsState == nil {
			http.Error(w, "not TLS", http.StatusInternalServerError)
			return
		}
		clientHello := r.Context().Value(ContextKey).(*ClientHello)
		if clientHello == nil || clientHello.info == nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "ja4:", Ja4(clientHello.info, false, false))
		fmt.Fprintln(w, "ja4_r:", Ja4(clientHello.info, false, true))
		fmt.Fprintln(w, "ja4_o:", Ja4(clientHello.info, true, false))
		fmt.Fprintln(w, "ja4_ro:", Ja4(clientHello.info, true, true))
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ja4_o and ja4_ro are not fixed, such as Chromium-based browsers. https://chromestatus.com/feature/5124606246518784")
	})
	server := http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if clientHello, ok := info.Context().Value(ContextKey).(*ClientHello); ok {
					clientHello.info = info
				}
				return nil, nil
			},
			InsecureSkipVerify: true,
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ContextKey, &ClientHello{})
		},
	}
	fmt.Println("open https://localhost:8443/")
	if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
		fmt.Println(err)
	}
}
