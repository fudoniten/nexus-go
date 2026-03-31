package main

import (
	"encoding/base64"
	"flag"
	"log"
	"os"

	"github.com/fudoniten/nexus-go/nexus"
	"github.com/fudoniten/nexus-go/nexus/challenge"
)

func parseFlags() (keyfile, domain, host, service, secret *string) {
	keyfile = flag.String("key", "", "Path at which to find signing key.")
	domain = flag.String("domain", "", "Domain to be challenged.")
	host = flag.String("host", "", "Hostname to be targeted by the challenge.")
	service = flag.String("service", "", "Service as which to identify with the server.")
	secret = flag.String("secret", "", "Challenge secret to store at `host.domain`.")
	flag.Parse()
	return
}

func createClient(domain, service *string, key []byte) (*nexus.NexusClient, error) {
	return nexus.New(*domain, *service, key)
}

func main() {
	keyfile, domain, host, service, secret := parseFlags()

	log.SetOutput(os.Stdout)

	log.Printf("domain: %v, host: %v, service: %v, secret: %v\n\n", *domain, *host, *service, *secret)

	encodedKey, err := os.ReadFile(*keyfile)
	if err != nil {
		panic(err)
	}
	key, err := base64.StdEncoding.DecodeString(string(encodedKey))
	if err != nil {
		panic(err)
	}

	client, err := createClient(domain, service, key)
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
