package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

type CredhubRotator struct {
	Prefix                 string
	CredhubBaseURL         string
	CredhubCACerts         string
	CredhubUAAClient       string
	CredhubUAAClientSecret string
}

const (
	actionPreDeploy  = 1
	actionPostDeploy = 2
)

// PrepareForNewDeploy is expected to:
// 1. Delete any certificates that are not CAs, they are always safe to regenerate.
// 2. For any certificates that are CAs, and only one active, create new, make it active, mark old as transitional.
// 3. Return a map of variables (such as foo_ca.certificate) that contains all the old CAs that are still in transitional state.
func (c *CredhubRotator) PrepareForNewDeploy() (map[string]string, error) {
	return c.doit(actionPreDeploy)
}

// PostSuccessfulDeploy is expected to:
// 1. Delete any certificates that are not CAs, they are always safe to regenerate.
// 2. For any certificates that are CAs, mark the transitional ones as not current.
func (c *CredhubRotator) PostSuccessfulDeploy() error {
	_, err := c.doit(actionPostDeploy)
	return err
}

func (c *CredhubRotator) doit(action int) (map[string]string, error) {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(c.CredhubCACerts)) {
		return nil, errors.New("CREDHUB_CA_CERT must be set and include PEMs")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: cp,
			},
		},
	}

	uaaURL, err := getUAAURL(client, c.CredhubBaseURL)
	if err != nil {
		return nil, err
	}

	uaaToken, err := getUAAToken(client, uaaURL, c.CredhubUAAClient, c.CredhubUAAClientSecret)
	if err != nil {
		return nil, err
	}

	creds, err := listCredentials(client, c.CredhubBaseURL, uaaToken, c.Prefix)
	if err != nil {
		return nil, err
	}

	certsToDelete := make(map[string]*credhubCredResp)
	certsToRotate := make(map[string]*credhubCredResp)
	for _, cred := range creds.Credentials {
		cd, err := getCred(client, c.CredhubBaseURL, uaaToken, cred.Name)
		if err != nil {
			return nil, err
		}
		if len(cd.Data) == 0 {
			return nil, errors.New("no creds returned")
		}

		for _, c := range cd.Data {
			if c.Type == "certificate" {
				asMap, ok := c.Value.(map[string]interface{})
				if !ok {
					return nil, errors.New("cannot decode cert type value")
				}
				certificateString, ok := asMap["certificate"].(string)
				if !ok {
					return nil, errors.New("cannot decode cert type value (2)")
				}

				block, _ := pem.Decode([]byte(certificateString))
				if block == nil {
					return nil, errors.New("no cert found")
				}
				if block.Type != "CERTIFICATE" {
					return nil, errors.New("pem not cert")
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, err
				}
				if cert.IsCA {
					certsToRotate[cred.Name] = cd
				} else {
					certsToDelete[cred.Name] = cd
				}
			}
		}
	}

	// delete all normal certs, as they can always safely be regenerated
	for certName := range certsToDelete {
		log.Println("Deleting leaf certificate: ", certName)
		err := deleteCred(client, c.CredhubBaseURL, uaaToken, certName)
		if err != nil {
			return nil, err
		}
	}

	rv := make(map[string]string)

	// now let's have fun with these...
	for certName, cd := range certsToRotate {
		key := fmt.Sprintf("%s.certificate", certName[len(c.Prefix)+1:])
		switch action {
		case actionPreDeploy:
			// only attempt rotation if we are in a clean state, ie exactly one active
			if len(cd.Data) == 1 {
				log.Println("Rotating CA:", certName)

				// get certificate ID - (this is different?)
				certID, err := getCertID(client, c.CredhubBaseURL, uaaToken, certName)
				if err != nil {
					return nil, err
				}

				// regenerate it
				err = makeNewTransitional(client, c.CredhubBaseURL, uaaToken, certID)
				if err != nil {
					return nil, err
				}

				// set the older one to transitional
				err = makeThisOneTransitional(client, c.CredhubBaseURL, uaaToken, certID, cd.Data[0].ID)
				if err != nil {
					return nil, err
				}

				rv[key] = fmt.Sprintf("%s\n%s", cd.Data[0].Value.(map[string]interface{})["certificate"], rv[key])
			} else {
				log.Println("More than one active cert found, we won't rotate for now:", certName)
				for _, cc := range cd.Data {
					if cc.Transitional {
						rv[key] = fmt.Sprintf("%s\n%s", cc.Value.(map[string]interface{})["certificate"], rv[key])
					}
				}
			}
		case actionPostDeploy:
			// delete old ones
			if len(cd.Data) == 1 {
				log.Println("Only one active cert found, no transitionals to delete:", certName)
			} else {
				log.Println("Removing transitional CA(s):", certName)

				// get certificate ID - (this is different?)
				certID, err := getCertID(client, c.CredhubBaseURL, uaaToken, certName)
				if err != nil {
					return nil, err
				}

				// set none as transitional
				err = makeThisOneTransitional(client, c.CredhubBaseURL, uaaToken, certID, "")
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return rv, nil
}

func makeThisOneTransitional(client *http.Client, baseURL, accessToken, certID, transitionalOne string) error {
	var reqData []byte
	if transitionalOne == "" {
		reqData = []byte(`{"version":null}`)
	} else {
		var err error
		reqData, err = json.Marshal(&(struct {
			S string `json:"version"`
		}{S: transitionalOne}))
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/certificates/%s/update_transitional_version", baseURL, certID), bytes.NewReader(reqData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("bad status code")
	}

	return nil
}

func makeNewTransitional(client *http.Client, baseURL, accessToken, certID string) error {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/v1/certificates/%s/regenerate", baseURL, certID), bytes.NewReader([]byte(`{"set_as_transitional":true}`)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("bad status code")
	}

	return nil
}

func getCertID(client *http.Client, baseURL, accessToken, name string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/certificates?%s", baseURL, (&url.Values{
		"name": []string{name},
	}).Encode()), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("bad status code")
	}

	var x struct {
		Certificates []struct {
			ID string `json:"id"`
		} `json:"certificates"`
	}
	err = json.NewDecoder(resp.Body).Decode(&x)
	if err != nil {
		return "", err
	}

	if len(x.Certificates) != 1 {
		return "", errors.New("wrong num certs")
	}

	if x.Certificates[0].ID == "" {
		return "", errors.New("no cert ID")
	}

	return x.Certificates[0].ID, nil
}

func deleteCred(client *http.Client, baseURL, accessToken, name string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/data?%s", baseURL, (&url.Values{
		"name": []string{name},
	}).Encode()), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return errors.New("bad status code")
	}

	return nil
}

type credhubCredResp struct {
	Data []struct {
		Type         string      `json:"type"`
		ID           string      `json:"id"`
		Transitional bool        `json:"transitional"`
		Value        interface{} `json:"value"` // poor choice of API surface...
	} `json:"data"`
}

func getCred(client *http.Client, baseURL, accessToken, name string) (*credhubCredResp, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/data?%s", baseURL, (&url.Values{
		"name":    []string{name},
		"current": []string{"true"},
	}).Encode()), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad status code")
	}

	var x credhubCredResp
	err = json.NewDecoder(resp.Body).Decode(&x)
	if err != nil {
		return nil, err
	}

	return &x, nil
}

type credhubListResponse struct {
	Credentials []struct {
		Name string `json:"name"`
	} `json:"credentials"`
}

func listCredentials(client *http.Client, baseURL, accessToken, path string) (*credhubListResponse, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/data?%s", baseURL, (&url.Values{
		"path": []string{path},
	}).Encode()), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad status code")
	}

	var x credhubListResponse
	err = json.NewDecoder(resp.Body).Decode(&x)
	if err != nil {
		return nil, err
	}

	return &x, nil
}

func getUAAToken(client *http.Client, uaaURL, clientID, clientSecret string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/oauth/token", uaaURL), bytes.NewReader([]byte((&url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
		"grant_type":    []string{"client_credentials"},
		"token_type":    []string{"jwt"},
	}).Encode())))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("bad status code")
	}

	var x struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&x)
	if err != nil {
		return "", err
	}

	if x.AccessToken == "" {
		return "", errors.New("no access token found in response")
	}
	return x.AccessToken, nil
}

func getUAAURL(client *http.Client, baseURL string) (string, error) {
	resp, err := client.Get(fmt.Sprintf("%s/info", baseURL))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("bad status code")
	}

	var x struct {
		AuthServer struct {
			URL string `json:"url"`
		} `json:"auth-server"`
	}
	err = json.NewDecoder(resp.Body).Decode(&x)
	if err != nil {
		return "", err
	}

	if x.AuthServer.URL == "" {
		return "", errors.New("no auth server URL found in response")
	}

	return x.AuthServer.URL, nil
}
