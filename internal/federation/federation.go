// Package federation exchanges a SAML response for temporary AWS credentials.
package federation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/yokonao/saml2sts/internal/saml"
)

// Credentials are temporary AWS credentials.
type Credentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
	Issued          time.Time `json:"issued"`
}

// Fresh reports whether c stays valid for at least margin, or half its
// lifetime when that is shorter, so short sessions are still reused.
func (c Credentials) Fresh(margin time.Duration) bool {
	margin = min(margin, c.Expiration.Sub(c.Issued)/2)
	return c.AccessKeyID != "" && time.Until(c.Expiration) > margin
}

// DefaultDuration is the session length every role allows.
const DefaultDuration = time.Hour

// DurationTooLong reports whether STS rejected the call because the duration
// asked for exceeds the role's maximum session duration.
func DurationTooLong(err error) bool {
	var ae smithy.APIError
	return errors.As(err, &ae) && ae.ErrorCode() == "ValidationError" &&
		strings.Contains(ae.ErrorMessage(), "MaxSessionDuration")
}

// AssumeRole calls AssumeRoleWithSAML. A zero duration leaves the session
// length to STS and the assertion's SessionDuration.
// A non-empty endpoint replaces the regional STS endpoint.
func AssumeRole(ctx context.Context, region, endpoint string, role saml.Role, samlResponse string, duration time.Duration) (Credentials, error) {
	// Built without the shared config, which may name this tool as the
	// credential_process of the active profile.
	opts := sts.Options{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
	}
	if endpoint != "" {
		opts.BaseEndpoint = aws.String(endpoint)
	}
	in := &sts.AssumeRoleWithSAMLInput{
		RoleArn:       aws.String(role.RoleARN),
		PrincipalArn:  aws.String(role.PrincipalARN),
		SAMLAssertion: aws.String(samlResponse),
	}
	if duration > 0 {
		in.DurationSeconds = aws.Int32(int32(duration / time.Second))
	}
	issued := time.Now()
	out, err := sts.New(opts).AssumeRoleWithSAML(ctx, in)
	if err != nil {
		return Credentials{}, err
	}
	c := out.Credentials
	return Credentials{
		AccessKeyID:     aws.ToString(c.AccessKeyId),
		SecretAccessKey: aws.ToString(c.SecretAccessKey),
		SessionToken:    aws.ToString(c.SessionToken),
		Expiration:      aws.ToTime(c.Expiration),
		Issued:          issued,
	}, nil
}
