// bench_origin_server.go — High-throughput TLS HTTP/1.1 file server for CI benchmarks.
//
// Replaces the Python origin in ci_bench_mitm.sh. Go's TLS + goroutine-per-connection
// model eliminates the single-threaded Python GIL bottleneck that caps multipath
// throughput at ~150 Mbps.
//
// Build:  go build -o bench_origin bench_origin_server.go
// Usage:  ./bench_origin -cert C -key K -port P -root DIR

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	cert := flag.String("cert", "", "TLS certificate file")
	key := flag.String("key", "", "TLS private key file")
	port := flag.Int("port", 8443, "Listen port")
	root := flag.String("root", ".", "File root directory")
	flag.Parse()

	if *cert == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "usage: bench_origin_server -cert C -key K [-port P] [-root DIR]")
		os.Exit(2)
	}

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench_origin_server: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if name == "." || name == "/" || name == ".." {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(absRoot, name))
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench_origin_server: listen: %v\n", err)
		os.Exit(1)
	}

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			NextProtos: []string{"http/1.1"},
		},
	}

	fmt.Printf("LISTENING %s\n", addr)
	os.Stdout.Sync()

	if err := server.ServeTLS(ln, *cert, *key); err != nil {
		fmt.Fprintf(os.Stderr, "bench_origin_server: %v\n", err)
		os.Exit(1)
	}
}
