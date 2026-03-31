package challenge

import (
	"testing"

	"github.com/fudoniten/nexus-go/nexus"
	"github.com/google/uuid"
)

func TestCreateChallengeRecord(t *testing.T) {
	client := &nexus.NexusClient{
		Server:  "example.com",
		Domain:  "example.com",
		Service: "example",
		Key:     []byte("example"),
	}

	host := "example.com"
	secret := "example"

	challengeID, err := CreateChallengeRecord(client, host, secret)
	if err != nil {
		t.Errorf("CreateChallengeRecord returned error: %v", err)
	}

	if challengeID == uuid.Nil {
		t.Error("CreateChallengeRecord returned nil challenge ID")
	}
}

func TestDeleteChallengeRecord(t *testing.T) {
	client := &nexus.NexusClient{
		Server:  "example.com",
		Domain:  "example.com",
		Service: "example",
		Key:     []byte("example"),
	}

	challengeID := uuid.New()

	err := DeleteChallengeRecord(client, challengeID)
	if err != nil {
		t.Errorf("DeleteChallengeRecord returned error: %v", err)
	}
}
