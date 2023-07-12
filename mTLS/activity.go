package mTLS

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
	"bytes"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

const (
	ivEndPoint = "endPoint"
	ivRequestBody = "requestBody"
	ivCert = "cert"
	ivKey = "key"
	ovResult = "responseCode"
)


var activityLog = logger.GetLogger("mTLS")

type mTLS struct {
	metadata *activity.Metadata
}

func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &mTLS{metadata: metadata}
}

func (a *mTLS) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements api.Activity.Eval - Create the hash
func (a *mTLS) Eval(context activity.Context) (done bool, err error) {

	activityLog.Info("Executing mTLS POST")


	if context.GetInput(ivEndPoint) == nil {
		// endPoint is not configured
		// return error to the engine
		return false, activity.NewError("EndPoing missing", "mTLS-404", nil)
	}
	endPoint := context.GetInput(ivEndPoint).(string)

	if context.GetInput(ivRequestBody) == nil {
		// no body 
		// return error to the engine
		return false, activity.NewError("No body was defined", "mTLS-500", nil)
	}
	requestBody := context.GetInput(ivRequestBody).(string)
	activityLog.Info(requestBody)

	if context.GetInput(ivCert) == nil {
		// certificate is not configured
		// return error to the engine
		return false, activity.NewError("No certificate", "MYPAUTH-401", nil)
	}
	username := context.GetInput(ivUserName).(string)

	if context.GetInput(ivKey) == nil {
		// key is not configured
		// return error to the engine
		return false, activity.NewError("No key", "MYPAUTH-401", nil)
	}
	key := context.GetInput(ivKey).(string)

	certPem := []byte(ivCert)
	keyPem := []byte(ivKey)

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		log.Fatal(err)
	}
	
	caCertPool := x509.NewCertPool()
+	caCertPool.AppendCertsFromPEM(certPem)
	
	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	jsonBody := []byte(ivRequestBody)
	bodyReader := bytes.NewReader(jsonBody)
	requestURL := fmt.Sprintf(ivEndPoint)
	

	req, err := client.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		log.Fatal("client: could not create request: %s\n", err)
		return false, activity.NewError("client: could not create request: %s\n", "MYPAUTH-500", nil)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal("client: error making http request: %s\n", err)
		return false, activity.NewError("client: error making http request: %s\n", "MYPAUTH-500", nil)
	}


	activityLog.Info("client: got response!\n")
	activityLog.Info("client: status code: %d\n", res.StatusCode)

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal("client: could not read response body: %s\n", err)
		return false, activity.NewError("client: could not read response body: %s\n", "MYPAUTH-500", nil)
	}
	activityLog.Info("client: response body: %s\n", resBody)
	
	context.SetOutput(ovResult, res.StatusCode)
	
	return true, nil
}
