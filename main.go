package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/fudoniten/nexus-go/nexus"
	"github.com/fudoniten/nexus-go/nexus/challenge"
)

func parseFlags() (keyfile, privateKeyfile, domain, host, service, secret *string) {
	keyfile = flag.String("key", "", "Path at which to find the shared HMAC key (legacy /api/v2). Exactly one of -key or -private-key is required.")
	privateKeyfile = flag.String("private-key", "", "Path at which to find the Ed25519 private key, as written by nexus-generate-key --keypair (/api/v3). Exactly one of -key or -private-key is required.")
	domain = flag.String("domain", "", "Domain to be challenged.")
	host = flag.String("host", "", "Hostname to be targeted by the challenge.")
	service = flag.String("service", "", "Service as which to identify with the server.")
	secret = flag.String("secret", "", "Challenge secret to store at `host.domain`.")
	flag.Parse()
	return
}

// loadSigner reads the key named by whichever of the two key flags was given,
// and builds a signer for the API version that key belongs to. Which flag was
// used decides which kind of key is accepted, so pointing a flag at the wrong
// file fails here with a clear message rather than as a 401 from the server.
func loadSigner(keyfile, privateKeyfile string) (nexus.Signer, error) {
	switch {
	case keyfile != "" && privateKeyfile != "":
		return nil, fmt.Errorf("specify only one of -key or -private-key, not both")
	case keyfile != "":
		encoded, err := os.ReadFile(keyfile)
		if err != nil {
			return nil, fmt.Errorf("error reading key file %v: %w", keyfile, err)
		}
		return nexus.ParseHMACKey(string(encoded))
	case privateKeyfile != "":
		encoded, err := os.ReadFile(privateKeyfile)
		if err != nil {
			return nil, fmt.Errorf("error reading private key file %v: %w", privateKeyfile, err)
		}
		return nexus.ParseEd25519Key(string(encoded))
	default:
		return nil, fmt.Errorf("a key file must be specified: -key (legacy HMAC, /api/v2) or -private-key (Ed25519, /api/v3)")
	}
}

func main() {
	keyfile, privateKeyfile, domain, host, service, secret := parseFlags()

	log.SetOutput(os.Stdout)

	log.Printf("domain: %v, host: %v, service: %v, secret: %v\n\n", *domain, *host, *service, *secret)

	signer, err := loadSigner(*keyfile, *privateKeyfile)
	if err != nil {
		log.Println(err)
		flag.Usage()
		os.Exit(1)
	}

	client, err := nexus.NewWithSigner(*domain, *service, signer)
	if err != nil {
		panic(err)
	}

	challenge_id, err := challenge.CreateChallengeRecord(client, *host, *secret)
	if err != nil {
		log.Printf("Failed to create challenge: %v", err)
		os.Exit(1)
	}
	log.Printf("created challenge: %v", challenge_id)

	err = challenge.DeleteChallengeRecord(client, challenge_id)
	if err != nil {
		panic(err)
	}
	log.Printf("deleted challenge: %v", challenge_id)

	return
}
