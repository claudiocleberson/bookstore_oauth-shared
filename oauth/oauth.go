package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/claudiocleberson/bookstore_utils-shared/utils/rest_err"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXIsPrivate = "X-Private"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
)

type oauthClient struct {
}

type oauthInterface interface {
}

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:client_id`
}

//Check if the request is a private request or not.
func IsPrivate(req *http.Request) bool {

	if req == nil {
		return false
	}

	return req.Header.Get(headerXIsPrivate) == "true"
}

func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(req.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func GetCallerId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(req.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func AuthenticateRequest(req *http.Request) rest_err.RestErr {
	if req == nil {
		return nil
	}

	cleanRequest(req)

	accessTokenId := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Code() == http.StatusNotFound {
			return nil
		}

		return err
	}

	req.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	req.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))

	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}

	req.Header.Del(headerXClientId)
	req.Header.Del(headerXCallerId)

}
func getAccessToken(accessTokenId string) (*accessToken, rest_err.RestErr) {

	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	if response == nil || response.Response == nil {
		return nil, rest_err.NewInternalServerError("invalid restClient response when trying to get Access token", errors.New("invalid response"))
	}

	if response.StatusCode > 299 {
		var restErr rest_err.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, rest_err.NewNotFoundError("invalid error interface when trying to get access token")
		}
		return nil, restErr
	}

	var token accessToken
	if err := json.Unmarshal(response.Bytes(), &token); err != nil {
		return nil, rest_err.NewInternalServerError("error when trying to unmarshal access token", errors.New("invalid json"))
	}

	return &token, nil
}
