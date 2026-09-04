package nexus

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"time"
)

type NexusClient struct {
	Server  string
	Domain  string
	Service string
	Signer  Signer
	Client  *http.Client
}

// APIVersion reports which version of the Nexus API this client talks to,
// which is determined by the kind of key it signs with.
func (c *NexusClient) APIVersion() APIVersion {
	return c.Signer.APIVersion()
}

// Endpoint builds a request path rooted at the API version this client
// speaks, so callers never have to hardcode /api/v2 or /api/v3.
func (c *NexusClient) Endpoint(format string, args ...any) string {
	return fmt.Sprintf("/api/%v", c.APIVersion()) + fmt.Sprintf(format, args...)
}

// Sign returns the Access-Signature value for a canonical request string.
func (c *NexusClient) Sign(content string) (string, error) {
	return c.Signer.Sign(content)
}

func selectSrvRecord(records []*net.SRV) *net.SRV {
	if len(records) == 0 {
		return nil
	}

	// Group records by priority
	priorityGroups := make(map[uint16][]*net.SRV)
	for _, record := range records {
		priorityGroups[record.Priority] = append(priorityGroups[record.Priority], record)
	}

	// Fetch the group with the lowest priority
	var priorities []uint16
	for p := range priorityGroups {
		priorities = append(priorities, p)
	}
	// Sort priorities to ensure we deal with the lowest first
	sort.Slice(priorities, func(i, j int) bool {
		return priorities[i] < priorities[j]
	})

	// Select from the lowest priority group
	bestGroup := priorityGroups[priorities[0]]
	totalWeight := uint16(0)
	for _, record := range bestGroup {
		totalWeight += record.Weight
	}
	target := rand.Intn(int(totalWeight))
	for _, record := range bestGroup {
		if target < int(record.Weight) {
			return record
		}
		target -= int(record.Weight)
	}
	return nil
}

func getServerFromSRV(domain string) (server string, err error) {
	var srvRecords []*net.SRV
	var lookupErr error
	for i := 0; i < 3; i++ {
		log.Print("attempting to get server from domain SRV records")
		_, srvRecords, lookupErr = net.LookupSRV("nexus", "tcp", domain)
		if lookupErr == nil && len(srvRecords) > 0 {
			target := selectSrvRecord(srvRecords)
			server = fmt.Sprintf("%v:%v", target.Target, target.Port)
			log.Printf("using server from SRV record: %v", server)
			return server, nil
		}
		time.Sleep(time.Second * 2)
	}
	err = fmt.Errorf("failed to get server from SRV records after 3 attempts")
	if lookupErr != nil {
		log.Printf("error fetching SRV records: %v", lookupErr)
		server = fmt.Sprintf("nexus.%v:443", domain)
		log.Printf("using default server: %v", server)
		return
	}
	if len(srvRecords) == 0 {
		server = fmt.Sprintf("nexus.%v:443", domain)
		log.Printf("no SRV records found, using default: %v", server)
		return
	}
	target := selectSrvRecord(srvRecords)
	server = fmt.Sprintf("%v:%v", target.Target, target.Port)
	log.Printf("using server from SRV record: %v", server)
	return
}

func getChallengeDomainFromTXT(domain string) (target string, err error) {
	var records []string
	var lookupErr error
	for i := 0; i < 3; i++ {
		log.Print("attempting to get challenge domain from TXT record")
		targetRecord := fmt.Sprintf("_nexus-domain.%v", domain)
		records, lookupErr = net.LookupTXT(targetRecord)
		if lookupErr == nil && len(records) > 0 {
			target = records[0]
			log.Printf("using challenge domain from TXT record: %v", target)
			return target, nil
		}
		time.Sleep(time.Second * 2)
	}
	err = fmt.Errorf("failed to get challenge domain from TXT record after 3 attempts")
	if lookupErr != nil {
		log.Printf("error fetching challenge domain from TXT record: %v", lookupErr)
		target = domain
		log.Printf("using default domain: %v", target)
		return
	}
	if len(records) == 0 {
		target = domain
		log.Printf("using default challenge domain: %v", target)
		return
	}
	target = records[0]
	log.Printf("using challenge domain from TXT record: %v", target)
	return
}

// New creates a client that authenticates with a shared HMAC secret against
// the legacy /api/v2 API. New clients should prefer NewWithSigner, which also
// accepts an Ed25519 key for the public-key /api/v3 API.
func New(domain, service string, key []byte) (client *NexusClient, err error) {
	return NewWithSigner(domain, service, NewHMACSigner(key))
}

// NewWithSigner creates a client that authenticates with the given signer.
// The signer decides both how requests are signed and which API version they
// are sent to.
func NewWithSigner(domain, service string, signer Signer) (client *NexusClient, err error) {
	log.SetOutput(os.Stdout)

	server, err := getServerFromSRV(domain)
	if err != nil {
		return
	}
	log.Printf("client server: %v", server)
	targetDomain, err := getChallengeDomainFromTXT(domain)
	if err != nil {
		return
	}
	log.Printf("client domain: %v", targetDomain)
	log.Printf("client service: %v", service)
	log.Printf("client api version: %v", signer.APIVersion())
	client = &NexusClient{
		Server:  server,
		Domain:  targetDomain,
		Service: service,
		Signer:  signer,
		Client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
	return
}
