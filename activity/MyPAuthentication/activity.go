package MyPAuthentication

import (
    "crypto/hmac"
    "crypto/sha256"
    b64 "encoding/base64"
	"time"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

const (
	ivKey = "key"
	ivClientId = "mypclientid"
	ivUserName = "mypusername"
	ivTS = "timestamp"
	ovResult = "authHeader"
)


var activityLog = logger.GetLogger("mypreferences-authentication-generator")

type MyPAuthenticationActivity struct {
	metadata *activity.Metadata
}

func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &MyPAuthenticationActivity{metadata: metadata}
}

func (a *MyPAuthenticationActivity) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements api.Activity.Eval - Create the hash
func (a *MyPAuthenticationActivity) Eval(context activity.Context) (done bool, err error) {

	activityLog.Info("Executing MyPreferences authentication activity")


	if context.GetInput(ivKey) == nil {
		// key is not configured
		// return error to the engine
		return false, activity.NewError("Key is not configured", "MYPAUTH-4001", nil)
	}
	key := context.GetInput(ivKey).(string)

	if context.GetInput(ivClientId) == nil {
		// client id is not configured
		// return error to the engine
		return false, activity.NewError("Client id is not configured", "MYPAUTH-4002", nil)
	}
	clientid := context.GetInput(ivClientId).(string)
	activityLog.Info(clientid)

	if context.GetInput(ivUserName) == nil {
		// username is not configured
		// return error to the engine
		return false, activity.NewError("User name is not configured", "MYPAUTH-4003", nil)
	}
	username := context.GetInput(ivUserName).(string)
	
	timestamp := time.Now().Add(time.Second * -30).Format(time.RFC3339)

	authHeader := "PNAUTHINFO3-HMAC-sha256 Credential=" + username + "/" + timestamp + " Signature=" + generateToken(key, clientid + ":" + username + ":" + timestamp)
	
	context.SetOutput(ovResult, authHeader)
	
	return true, nil
}

func generateToken(secret string, data string) string {


    // Create a new HMAC by defining the hash type and the key (as byte array)
    h := hmac.New(sha256.New, []byte(secret))

    // Write Data to it
    h.Write([]byte(data))

    // Get result and encode as base64 string
    sha := b64.StdEncoding.EncodeToString([]byte(h.Sum(nil)))

    return sha
}