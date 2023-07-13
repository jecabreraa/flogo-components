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
	tc.SetInput("endPoint", "https://api-t.cloud.pge.com/on/customercare/v1/UpdateNotificationPreferences")
	tc.SetInput("requestBody", '{"customerPreferences":[{"action":"ADD","channel":"EML","entity":"ACCT","entityId":"1456135911","categoryType":"APTNOTIFY","personId":"9403239805","type":"PRIM","updateIdInfo":"MXUR","updateSource":"CSRO"}]}')
	tc.SetInput("cert", "-----BEGIN CERTIFICATE-----
MIIDiTCCAnGgAwIBAgIUONdzxRaBefQDbjRMU+P2+JIG0y4wDQYJKoZIhvcNAQEL
BQAwUzELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0dlb3JnaWExDzANBgNVBAcMBkR1
bHV0aDEhMB8GA1UEAwwYUEdFLVBOLU11dHVhbEF1dGhTdGFnaW5nMCAXDTIzMDcw
MzE3MTkwOVoYDzIwNTMwODE0MTcxOTA5WjBTMQswCQYDVQQGEwJVUzEQMA4GA1UE
CAwHR2VvcmdpYTEPMA0GA1UEBwwGRHVsdXRoMSEwHwYDVQQDDBhQR0UtUE4tTXV0
dWFsQXV0aFN0YWdpbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDG
P7KrI5xdnwrodCDMDjo55ZW/W+gQoR2xXnk+4SpIjC1mfX7mxNiODGIrMWPUBXcE
7NhLGMBSASt58l14jg2gt1pl6dpmwUvcBgO7K1R0jDvUFGThheHWiV+LoG+v4nXh
IYE+deeluFOGDMeA+MvRWmN7gKBgLGy4x3MUqtQjlVuOIFL6dk/ceSG0yWz7r7fv
07fJh8ErI9IOhbDRi7GOhaMZwzawQ5TUYtxHR1GccF9ywNB4IGsJPyffXOScJRLm
WrUORJm9ZpESR8hrwglFxc0SdQ3WonSMXPkV3YRci5GgDHqaWO9Ni+nn9gOnCO4R
35DbF1WuPE121L3BRH9HAgMBAAGjUzBRMB0GA1UdDgQWBBSlX1ABeHqky9rTkV9D
a1RgX8jE1TAfBgNVHSMEGDAWgBSlX1ABeHqky9rTkV9Da1RgX8jE1TAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAtB/y16t/mLc6oBtLtg90Ut+dG
4PrkTs1qLhBm4n0OaKgraQNdGokmUA0I7viINullsP7l1d9Y25xvjjZUoZS19e1R
gKsfRJ0ULcKLCDfhgAYEEQyLnZQdzcQoGc2lfTe1QFR1uyptpymF+jNcfqw8/L6i
9OhSusAf5g15JPLREMvlNh2Xy656HPPK+j0OEjZNupZVQZ3qwo18YBBclNiHdf9x
QFNdrrWVh6aY4w1am98wfK37LDO+PrnZdrQFQuIN+5rxXtFSosvRRD76Ubyhlxaa
ZYf6Kyx3fsgpQCD4jeriOr99ZiwPxCr1kISnBLI5qo+1J1DSo4tNTLoznD20
-----END CERTIFICATE-----")
	tc.SetInput("key", "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxj+yqyOcXZ8K6HQgzA46OeWVv1voEKEdsV55PuEqSIwtZn1+
5sTYjgxiKzFj1AV3BOzYSxjAUgErefJdeI4NoLdaZenaZsFL3AYDuytUdIw71BRk
4YXh1olfi6Bvr+J14SGBPnXnpbhThgzHgPjL0Vpje4CgYCxsuMdzFKrUI5VbjiBS
+nZP3HkhtMls+6+379O3yYfBKyPSDoWw0YuxjoWjGcM2sEOU1GLcR0dRnHBfcsDQ
eCBrCT8n31zknCUS5lq1DkSZvWaREkfIa8IJRcXNEnUN1qJ0jFz5Fd2EXIuRoAx6
mljvTYvp5/YDpwjuEd+Q2xdVrjxNdtS9wUR/RwIDAQABAoIBADTQNVXYN8jNHMfO
YApcY/CWk+0Vm94KPfHJfD1fGLeY+GNMXWk22YYGEIT3NGQATLO4MOrYnit6ek2T
XolGNqUxE1kBEpi7N+1WgNn08hvWW/3krPdThlVz5Us6I2bUyph+J4MvP9XrI/0b
HG7kWM/d55C4NIFKdHBJWgQQelE7+b4hArUuerOsgpYXLHo2zs3uxipq7BASqNUm
cZdDrBgoZCp+qBGRf9+1Ahd+PomWUVdaCtpiFYH+R3oU36p+Xwjv6iPMzChPVSI6
V05NNBgsW6cUmHalhqZiy2Eiky/XKU9Y0wgcrpDcQfxtqrN/uVZsyRYkPtnB++Sr
/v57FuECgYEA6N5mOvCt+7AGegGqOC8/7S0FX+L7RzqjQ+ZQ8tWpr04lgOI3p/eU
kjxO4a81IwPm00VcvyzFKbAWQDju4HxZVWfI9yL8wpN6nW5Jz+nB3ItSG0wTTX93
gTl3IJB6lEHW+evIg4InieyIsNuEXQSOPAhtuejn7L5RZWN1V3lLEXECgYEA2fDz
hCypsx0i/NLmZMyfhQNjQjJXESEC3biLNpN6nYFH+qS2lb3dsL4ZydFaqRAlF8mx
KYajvFb6ZuABg6Cq8je/hLVhcUyBHHQ2mxS13zMuCI7wDAqoI2Ahxs8rxXGbhEwz
Y/t49K+5yw1Mq0uJXFv3QAWJDyQxf71GCZ5/wDcCgYBbRag+G82lo6W2NmbYZLSi
qo27uoSQs4wAdgpuU46RloiejowP+rsx4g9s57ZlBgd38WzbxZl1sH3YKDiAplyB
XA9pxj3ZqeJaSDsIEfAZGEZTSqsaKgbWEIb/rYFOEMxI4sCRwvbqWVpuL2we5UU2
hHs1bfNRWHsgyS3Z3kGtEQKBgG2eDq2FVVl8pzNo1G8QqI9bc9pAvaAk7W8dug+a
QArmkpCTti480DtsckYbIbF1KGL9lDkhukspqEqEEt7kufaYaaDTJg65fxsTrL91
vEBmWpn9Yul7lrQsTvDTFN37VVBGj3aTbnQLyrRBnTVvCcjFjOfLoPNXrfnk9kwy
R2kjAoGAK48wT7+O3MyyefJeC+d4SqjSENtC0URWuXQsJlixE0qgAVxTmBjH/rnN
a2lZktXNFkE/Gw5zlpaRG0InsOQlOfG/pFr2Vs6BiiZnBeJhktNMmRJSE6HBh/0n
YsU/8Q2dWHkAZwfZDcVhmkuRa6xEum0k31QSGmX/55yFCqYtcZM=
-----END RSA PRIVATE KEY-----")

	_, err := act.Eval(tc)
	assert.Nil(t, err)

	result := tc.GetOutput("responseCode")
	assert.Equal(t, result)

	t.Log(result)
}
