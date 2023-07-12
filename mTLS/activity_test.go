package MyPAuthentication

import (
	"io/ioutil"
	"testing"

	"github.com/TIBCOSoftware/flogo-contrib/action/flow/test"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/stretchr/testify/assert"
)

var activityMetadata *activity.Metadata

func getActivityMetadata() *activity.Metadata {
	if activityMetadata == nil {
		jsonMetadataBytes, err := ioutil.ReadFile("activity.json")
		if err != nil {
			panic("No Json Metadata found for activity.json path")
		}
		activityMetadata = activity.NewMetadata(string(jsonMetadataBytes))
	}
	return activityMetadata
}

func TestActivityRegistration(t *testing.T) {
	act := NewActivity(getActivityMetadata())
	if act == nil {
		t.Error("Activity Not Registered")
		t.Fail()
		return
	}
}

func TestEval(t *testing.T) {
	act := NewActivity(getActivityMetadata())
	
	tc := test.NewTestActivityContext(act.Metadata())
	
	//setup attrs
	tc.SetInput("key", "kvh2TPjwE2Xg")
	tc.SetInput("clientId", "KPMG_Profiles")
	tc.SetInput("userName", "kpmg_pn_jcabrera")
	tc.SetInput("timeStamp", "2020-10-06T18:09:12.667Z")

	_, err := act.Eval(tc)
	assert.Nil(t, err)

	result := tc.GetOutput("result")
	assert.Equal(t, "PNAUTHINFO3-HMAC-sha256 Credential=kpmg_pn_jcabrera/2020-10-06T18:09:12.667Z Signature=Jyg86v+4FRMYdDSfoIEhLCcvGlq83fapLMIwgWF9VDY=", result)

	t.Log(result)
}