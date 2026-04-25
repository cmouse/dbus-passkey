package types

// MakeCredentialOptions holds caller-supplied options for credential creation.
type MakeCredentialOptions struct {
	RPID                  string
	RPName                string
	UserID                []byte
	UserName              string
	UserDisplayName       string
	Challenge             []byte
	PubKeyCredParams      []CredentialParam
	ExcludeCredentials    []CredentialDescriptor
	AuthenticatorAttachment string
	ResidentKey           string
	UserVerification      string
	Attestation           string
	TimeoutMS             uint32
}

// GetAssertionOptions holds caller-supplied options for assertion.
type GetAssertionOptions struct {
	RPID             string
	Challenge        []byte
	AllowCredentials []CredentialDescriptor
	UserVerification string
	TimeoutMS        uint32
}

// CredentialParam is a { type, alg } pair from pub_key_cred_params.
type CredentialParam struct {
	Type string
	Alg  int32
}

// CredentialDescriptor is { type, id, transports }.
type CredentialDescriptor struct {
	Type       string
	ID         []byte
	Transports []string
}

// MakeCredentialResult holds output of a successful MakeCredential.
type MakeCredentialResult struct {
	CredentialID      []byte
	AttestationObject []byte
	ClientDataJSON    []byte
	Transports        []string
	ProviderID        string
}

// GetAssertionResult holds output of a successful GetAssertion.
type GetAssertionResult struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
	ClientDataJSON    []byte
	ProviderID        string
}

// ErrorResult holds error info for a failed operation.
type ErrorResult struct {
	Code    string
	Message string
}

// ResponseCode is the response code for Request.Response signal.
type ResponseCode uint32

const (
	ResponseSuccess     ResponseCode = 0
	ResponseCancelled   ResponseCode = 1
	ResponseInteractionEnded ResponseCode = 2
	ResponseError       ResponseCode = 3
)

// Candidate describes an authenticator candidate for UI selection.
type Candidate struct {
	ProviderID      string
	ProviderName    string
	ProviderType    string
	Transports      []string
	CredentialID    []byte
	UserName        string
	UserDisplayName string
}
