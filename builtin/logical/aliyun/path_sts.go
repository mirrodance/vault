package aliyun

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathSTS(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sts/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `Lifetime of the token in seconds.
Aliyun documentation excerpt: The duration, in seconds, that the credentials
should remain valid. Acceptable durations for RAM user sessions range from 900
seconds (15 minutes) to 129600 seconds (36 hours), with 43200 seconds (12
hours) as the default. Sessions for Aliyun account owners are restricted to a
maximum of 3600 seconds (one hour). If the duration is longer than one hour,
the session for Aliyun account owners defaults to one hour.`,
				Default: 3600,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathSTSRead,
			logical.UpdateOperation: b.pathSTSRead,
		},

		HelpSynopsis:    pathSTSHelpSyn,
		HelpDescription: pathSTSHelpDesc,
	}
}

func (b *backend) pathSTSRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	policyName := d.Get("name").(string)
	ttl := d.Get("ttl").(int)

	// Read the policy
	entry, err := req.Storage.Get(ctx, "policy/"+policyName)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}
	if entry == nil {
		return logical.ErrorResponse(fmt.Sprintf("Role '%s' not found", policyName)), nil
	}

	var result roleConfig
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, errwrap.Wrapf("error decode policy: {{err}}", err)
	}
	if strings.HasPrefix(result.Policy, "acs:") {
		if strings.Contains(result.Policy, ":role/") {
			return b.assumeRole(
				ctx,
				req.Storage,
				req.DisplayName, policyName, result.Policy,
				ttl,
			)
		}

		return logical.ErrorResponse(
				"Can't generate STS credentials for a managed policy; use a role to assume or an inline policy instead"),
			logical.ErrInvalidRequest
	}
	// Use the helper to create the secret
	return b.secretTokenCreate(
		ctx,
		req.Storage,
		req.DisplayName, policyName, result.Policy,
		ttl,
	)
}

const pathSTSHelpSyn = `
Generate an access key pair + security token for a specific role.
`

const pathSTSHelpDesc = `
This path will generate a new, never before used key pair + security token for
accessing Aliyun. The RAM policy used to back this key pair will be
the "name" parameter. For example, if this backend is mounted at "aliyun",
then "aliyun/sts/deploy" would generate access keys for the "deploy" role.

Note, these credentials are instantiated using the Aliyun STS backend.

The access keys will have a lease associated with them, but revoking the lease
does not revoke the access keys.
`
