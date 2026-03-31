package challenge


import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"github.com/fudoniten/nexus-go/nexus"
	"github.com/google/uuid"
)

type NexusCreateChallengeReq struct {
	Host   string `json:"host"`
	Secret string `json:"secret"`
}


func CreateChallengeRecord(client *nexus.NexusClient, host string, secret string) (uuid.UUID, error) {
	log.Printf("creating challenge request at host %v", host)
	challenge_id := uuid.New()
	endpoint := fmt.Sprintf("/api/v2/domain/%v/challenge/%v",
		client.Domain,
		challenge_id)
	url := fmt.Sprintf("https://%v%v", client.Server, endpoint)
	log.Printf("url: %v", url)
	content := &bytes.Buffer{}
	reqBody := NexusCreateChallengeReq{
		Host:   host,
		Secret: secret,
	}
	if err := json.NewEncoder(content).Encode(reqBody); err != nil {
		err = fmt.Errorf("error encoding request body: %w", err)
		log.Println(err)
		return uuid.Nil, err
	}
	ts := time.Now().Unix()
	sigstring := fmt.Sprintf("%v%v%v%v", "PUT", endpoint, ts, content)
	sig, err := sign(sigstring, client.Key)
	if err != nil {
		return uuid.Nil, err
	}
	req, err := http.NewRequest("PUT", url, content)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Access-Signature", sig)
	req.Header.Set("Access-Timestamp", fmt.Sprintf("%v", ts))
	req.Header.Set("Service", client.Service)
	resp, err := client.Client.Do(req)
	if err != nil {
		err = fmt.Errorf("error sending challenge: %w", err)
		log.Println(err)
		return uuid.Nil, err
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("failed to create challenge (status code %v)", resp.StatusCode)
		log.Println(err)
		return uuid.Nil, err
	}
	log.Print("challenge successfully created")
	return challenge_id, nil
}

func DeleteChallengeRecord(client *nexus.NexusClient, challenge_id uuid.UUID) error {
	endpoint := fmt.Sprintf("/api/v2/domain/%v/challenge/%v",
		client.Domain,
		challenge_id)
	url := fmt.Sprintf("https://%v%v", client.Server, endpoint)
	log.Printf("deleting challenge record %v\n", challenge_id)
	ts := time.Now().Unix()
	sigstring := fmt.Sprintf("%v%v%v", "DELETE", endpoint, ts)
	sig, err := sign(sigstring, client.Key)
	if err != nil {
		err = fmt.Errorf("error signing delete request: %w", err)
		log.Println(err)
		return err
	}
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		err = fmt.Errorf("error creating delete request: %w", err)
		log.Println(err)
		return err
	}
	req.Header.Set("Access-Signature", sig)
	req.Header.Set("Access-Timestamp", fmt.Sprintf("%v", ts))
	req.Header.Set("Service", client.Service)
	resp, err := client.Client.Do(req)
	if err != nil {
		err = fmt.Errorf("error sending delete request: %w", err)
		log.Println(err)
		return err
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("failed to delete challenge (status code %v)", resp.StatusCode)
		log.Println(err)
		return err
	}
	return nil
}

func sign(content string, key []byte) (sig string, err error) {
	h := hmac.New(sha512.New, key)
	h.Write([]byte(content))
	sigbytes := h.Sum(nil)
	sig = base64.StdEncoding.EncodeToString(sigbytes)
	return
}
