package nexus

import (
	"net/http"
	"time"
)

type NexusClient struct {
	Server  string
	Domain  string
	Service string
	Key     []byte
	Client  *http.Client
}

func New(server, domain, service string, key []byte) (client *NexusClient, err error) {
	client = &NexusClient{
		Server:  server,
		Domain:  domain,
		Service: service,
		Key:     key,
		Client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
	return
}
