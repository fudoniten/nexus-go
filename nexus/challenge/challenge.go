package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/fudoniten/nexus-go/nexus"
	"github.com/google/uuid"
)

type NexusCreateChallengeReq struct {
	Host   string `json:"host"`
	Secret string `json:"secret"`
}

type NexusDeleteChallengeResp struct {
}

func sign(content string, key []byte) (sig string, err error) {
	h := hmac.New(sha512.New, key)
	h.Write([]byte(content))
	sigbytes := h.Sum(nil)
	sig = base64.StdEncoding.EncodeToString(sigbytes)
	return
}

func CreateChallengeRecord(client *nexus.NexusClient, host string, secret string) (challenge_id uuid.UUID, err error) {
	challenge_id = uuid.New()
	endpoint := fmt.Sprintf("/api/v2/domain/%v/challenge/%v",
		client.Domain,
		challenge_id)
	url := fmt.Sprintf("https://%v%v", client.Server, endpoint)
	content := &bytes.Buffer{}
	reqBody := NexusCreateChallengeReq{
		Host:   host,
		Secret: secret,
	}
	if json.NewEncoder(content).Encode(reqBody); err != nil {
		return
	}
	ts := time.Now().Unix()
	sigstring := fmt.Sprintf("%v%v%v%v", "PUT", endpoint, ts, content)
	fmt.Printf("%v\n\n", sigstring)
	sig, err := sign(sigstring, client.Key)
	if err != nil {
		return
	}
	req, err := http.NewRequest("PUT", url, content)
	req.Header.Set("Access-Signature", sig)
	req.Header.Set("Access-Timestamp", fmt.Sprintf("%v", ts))
	req.Header.Set("Service", client.Service)
	resp, err := client.Client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("failed to create challange (%v)", resp.StatusCode))
		return
	}
	return
}

func DeleteChallengeRecord(client *nexus.NexusClient, challenge_id uuid.UUID) (err error) {
	endpoint := fmt.Sprintf("/api/v2/domain/%v/challenge/%v",
		client.Domain,
		challenge_id)
	url := fmt.Sprintf("https://%v%v", client.Server, endpoint)
	ts := time.Now().Unix()
	sigstring := fmt.Sprintf("%v%v%v", "DELETE", endpoint, ts)
	fmt.Printf("%v\n\n", sigstring)
	sig, err := sign(sigstring, client.Key)
	if err != nil {
		return
	}
	req, err := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Access-Signature", sig)
	req.Header.Set("Access-Timestamp", fmt.Sprintf("%v", ts))
	req.Header.Set("Service", client.Service)
	resp, err := client.Client.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("failed to delete challange (%v)", resp.StatusCode))
		return
	}
	return
}
