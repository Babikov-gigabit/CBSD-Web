// Command devfixture builds a fake CBSD workdir so the UI can be developed
// and tested without FreeBSD:
//
//	go run ./tools/devfixture -dir /tmp/cbsd-dev
package main

import (
	"flag"
	"log"

	"github.com/cbsd-web/cbsd-web/internal/devfixture"
)

func main() {
	dir := flag.String("dir", "/tmp/cbsd-dev", "fake workdir")
	flag.Parse()
	if err := devfixture.Build(*dir); err != nil {
		log.Fatal(err)
	}
	log.Printf("fixture ready in %s", *dir)
}
