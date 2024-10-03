package nexus

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"time"
)

type NexusClient struct {
	Server  string
	Domain  string
	Service string
	Key     []byte
	Client  *http.Client
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

func getServer(domain string) (server string, err error) {
	_, srvRecords, err := net.LookupSRV("nexus", "tcp", domain)
	if err != nil {
		return
	}
	if len(srvRecords) == 0 {
		server = fmt.Sprintf("nexus.%v:443", domain)
		return
	}
	target := selectSrvRecord(srvRecords)
	server = fmt.Sprintf("%v:%v", target.Target, target.Port)
	return
}

func getTargetDomain(domain string) (target string, err error) {
	targetRecord := fmt.Sprintf("_nexus-domain.%v", domain)
	records, err := net.LookupTXT(targetRecord)
	if err != nil {
		return
	}
	if len(records) == 0 {
		target = domain
		return
	}
	target = records[0]
	return
}

func New(domain, service string, key []byte) (client *NexusClient, err error) {
	server, err := getServer(domain)
	if err != nil {
		return
	}
	log.Printf("client server: %v", server)
	targetDomain, err := getTargetDomain(domain)
	if err != nil {
		return
	}
	log.Printf("client domain: %v", targetDomain)
	log.Printf("client service: %v", service)
	client = &NexusClient{
		Server:  server,
		Domain:  targetDomain,
		Service: service,
		Key:     key,
		Client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
	return
}
