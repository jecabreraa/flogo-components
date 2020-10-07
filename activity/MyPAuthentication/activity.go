package MyPAuthentication

import (
    "crypto/hmac"
    "crypto/sha256"
    b64 "encoding/base64"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

const (
	ivField1 = "key"
	ivField2 = "clientId"
	ivField3 = "userName"
	ivField4 = "timeStamp"
	ovResult = "result"
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
func (a *MyPAuthenticationActivity) Eval(ctx activity.Context) (done bool, err error) {

	activityLog.Info("Executing MyPreferences authentication activity")


	if context.GetInput(ivField1) == nil {
		// key is not configured
		// return error to the engine
		return false, activity.NewError("Key is not configured", "MYPAUTH-4001", nil)
	}
	key := context.GetInput(ivField1).(string)

	if context.GetInput(ivField2) == nil {
		// client id is not configured
		// return error to the engine
		return false, activity.NewError("Client id is not configured", "MYPAUTH-4002", nil)
	}
	clientid := context.GetInput(ivField2).(string)

	if context.GetInput(ivField3) == nil {
		// username is not configured
		// return error to the engine
		return false, activity.NewError("User name is not configured", "MYPAUTH-4003", nil)
	}
	username := context.GetInput(ivField3).(string)

	if context.GetInput(ivField4) == nil {
		// Not testing.  Calculate actual time stamp.
		currentTime := time.Now()
		rfc3339Time := currentTime.Format(time.RFC3339)
		timeStamp := rfc3339Time.value[:strings.Index(rfc3339Time, "Z")]
	}
	else {
		timestamp := context.GetInput(ivField4).(string)
	}
	authHeader := "PNAUTHINFO3-HMAC-sha256 Credential=" + userName + "/" + timeStamp + " Signature=" + generateHash(key, clientid + ":" + username + ":" + timeStamp)
	
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