// Command genkey prints a fresh random 256-bit KEK as an environment line.
//
//	go run ./cmd/genkey v1   ->   KEK_V1=<base64>
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	id := "v1"
	if len(os.Args) > 1 {
		id = os.Args[1]
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("KEK_%s=%s\n", strings.ToUpper(id), base64.StdEncoding.EncodeToString(key))
}
