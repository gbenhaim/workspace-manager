package v1alpha1

type SignupStatusReason = string

var SignedUp SignupStatusReason = "SignedUp"
var NotSignedUp SignupStatusReason = "NotSignedUp"
var UnknownSignUpStatus SignupStatusReason = "Unknown"

type SignupStatus struct {
	Ready  bool               `json:"ready"`
	Reason SignupStatusReason `json:"reason"`
}

type Signup struct {
	SignupStatus SignupStatus `json:"status"`
}
