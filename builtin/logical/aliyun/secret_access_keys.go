package aliyun

import (
	"context"
	"fmt"
	"math/rand"

	"time"

	"regexp"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const SecretAccessKeyType = "access_keys"

func secretAccessKeys(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretAccessKeyType,
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access Key",
			},

			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret Key",
			},
			"security_token": {
				Type:        framework.TypeString,
				Description: "Security Token",
			},
		},

		Renew:  b.secretAccessKeysRenew,
		Revoke: secretAccessKeysRevoke,
	}
}

func genUsername(displayName, policyName, userType string) (ret string, warning string) {
	var midString string

	switch userType {
	case "ram_user":
		// RAM users are capped at 64 chars; this leaves, after the beginning and
		// end added below, 42 chars to play with.
		midString = fmt.Sprintf("%s-%s-",
			normalizeDisplayName(displayName),
			normalizeDisplayName(policyName))
		if len(midString) > 42 {
			midString = midString[0:42]
			warning = "the calling token display name/RAM policy name were truncated to fit into RAM username length limits"
		}
	case "sts":
		// Capped at 32 chars, which leaves only a couple of characters to play
		// with, so don't insert display name or policy name at all
	}

	ret = fmt.Sprintf("vault-%s%d-%d", midString, time.Now().Unix(), rand.Int31n(10000))
	return
}

func (b *backend) secretTokenCreate(ctx context.Context, s logical.Storage,
	displayName, policyName, policy string,
	lifeTimeInSeconds int) (*logical.Response, error) {
	client, err := clientSTS(ctx, s)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	username, usernameWarning := genUsername(displayName, policyName, "sts")

	generateSessionAccessKeyRequest := sts.CreateGenerateSessionAccessKeyRequest()
	generateSessionAccessKeyRequest.Scheme = requests.HTTPS
	generateSessionAccessKeyRequest.DurationSeconds = requests.NewInteger(lifeTimeInSeconds)
	tokenResp, err := client.GenerateSessionAccessKey(generateSessionAccessKeyRequest)

	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Error generating STS keys: %s", err)), nil
	}

	resp := b.Secret(SecretAccessKeyType).Response(map[string]interface{}{
		"access_key":     tokenResp.SessionAccessKey.SessionAccessKeyId,
		"secret_key":     tokenResp.SessionAccessKey.SessionAccessKeySecret,
		"security_token": "",
	}, map[string]interface{}{
		"username": username,
		"policy":   policy,
		"is_sts":   true,
	})

	// Set the secret TTL to appropriately match the expiration of the token
	expiration, err := time.Parse("2006-01-02T15:04:05Z", tokenResp.SessionAccessKey.Expiration)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error parse expiration: %s", tokenResp.SessionAccessKey.Expiration)), nil
	}
	resp.Secret.TTL = time.Until(expiration)

	// STS are purposefully short-lived and aren't renewable
	resp.Secret.Renewable = false

	if usernameWarning != "" {
		resp.AddWarning(usernameWarning)
	}

	return resp, nil
}

func (b *backend) assumeRole(ctx context.Context, s logical.Storage,
	displayName, policyName, policy string,
	lifeTimeInSeconds int) (*logical.Response, error) {
	STSClient, err := clientSTS(ctx, s)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	username, usernameWarning := genUsername(displayName, policyName, "sts")

	assumeRoleRequest := sts.CreateAssumeRoleRequest()
	assumeRoleRequest.Scheme = requests.HTTPS
	assumeRoleRequest.RoleArn = policy
	assumeRoleRequest.RoleSessionName = username
	assumeRoleRequest.DurationSeconds = requests.NewInteger(lifeTimeInSeconds)
	tokenResp, err := STSClient.AssumeRole(assumeRoleRequest)

	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Error assuming role: %s", err)), nil
	}

	resp := b.Secret(SecretAccessKeyType).Response(map[string]interface{}{
		"access_key":     tokenResp.Credentials.AccessKeyId,
		"secret_key":     tokenResp.Credentials.AccessKeySecret,
		"security_token": tokenResp.Credentials.SecurityToken,
	}, map[string]interface{}{
		"username": username,
		"policy":   policy,
		"is_sts":   true,
	})

	// Set the secret TTL to appropriately match the expiration of the token
	expiration, err := time.Parse("2006-01-02T15:04:05Z", tokenResp.Credentials.Expiration)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error parse expiration: %s", tokenResp.Credentials.Expiration)), nil
	}
	resp.Secret.TTL = time.Until(expiration)

	// STS are purposefully short-lived and aren't renewable
	resp.Secret.Renewable = false

	if usernameWarning != "" {
		resp.AddWarning(usernameWarning)
	}

	return resp, nil
}

func (b *backend) secretAccessKeysCreate(
	ctx context.Context,
	s logical.Storage,
	displayName, policyType string, policy string, policyName string) (*logical.Response, error) {
	client, err := clientRAM(ctx, s)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	username, usernameWarning := genUsername(displayName, policyName, "ram_user")

	// Write to the WAL that this user will be created. We do this before
	// the user is created because if switch the order then the WAL put
	// can fail, which would put us in an awkward position: we have a user
	// we need to rollback but can't put the WAL entry to do the rollback.
	walID, err := framework.PutWAL(ctx, s, "user", &walUser{
		UserName: username,
	})
	if err != nil {
		return nil, errwrap.Wrapf("error writing WAL entry: {{err}}", err)
	}

	// Create the user
	createUserRequest := ram.CreateCreateUserRequest()
	createUserRequest.UserName = username
	createUserRequest.RpcRequest.Scheme = requests.HTTPS
	_, err = client.CreateUser(createUserRequest)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Error creating RAM user: %s", err)), nil
	}

	if policyType == "" {
		policyType = "Custom"
		// Create policy
		createPolicyRequest := ram.CreateCreatePolicyRequest()
		createPolicyRequest.RpcRequest.Scheme = requests.HTTPS
		createPolicyRequest.PolicyName = policyName
		createPolicyRequest.Description = "vault policy"
		createPolicyRequest.PolicyDocument = policy
		_, err = client.CreatePolicy(createPolicyRequest)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf(
				"Error create policy: %s", err)), nil
		}
	}
	// Attach exist policy to user.
	attachPolicyToUserRequest := ram.CreateAttachPolicyToUserRequest()
	attachPolicyToUserRequest.UserName = username
	attachPolicyToUserRequest.RpcRequest.Scheme = requests.HTTPS
	attachPolicyToUserRequest.PolicyName = policyName
	attachPolicyToUserRequest.PolicyType = policyType
	// Attach existing policy against user
	_, err = client.AttachPolicyToUser(attachPolicyToUserRequest)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Error attaching user policy: %s", err)), nil
	}

	// Create the keys
	createAccessKeyRequest := ram.CreateCreateAccessKeyRequest()
	createAccessKeyRequest.UserName = username
	createAccessKeyRequest.Scheme = requests.HTTPS
	keyResp, err := client.CreateAccessKey(createAccessKeyRequest)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Error creating access keys: %s", err)), nil
	}

	// Remove the WAL entry, we succeeded! If we fail, we don't return
	// the secret because it'll get rolled back anyways, so we have to return
	// an error here.
	if err := framework.DeleteWAL(ctx, s, walID); err != nil {
		return nil, errwrap.Wrapf("failed to commit WAL entry: {{err}}", err)
	}

	// Return the info!
	resp := b.Secret(SecretAccessKeyType).Response(map[string]interface{}{
		"access_key":     keyResp.AccessKey.AccessKeyId,
		"secret_key":     keyResp.AccessKey.AccessKeySecret,
		"security_token": nil,
	}, map[string]interface{}{
		"username": username,
		"policy":   policy,
		"is_sts":   false,
	})

	lease, err := b.Lease(ctx, s)
	if err != nil || lease == nil {
		lease = &configLease{}
	}

	resp.Secret.TTL = lease.Lease
	resp.Secret.MaxTTL = lease.LeaseMax

	if usernameWarning != "" {
		resp.AddWarning(usernameWarning)
	}

	return resp, nil
}

func (b *backend) secretAccessKeysRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// STS already has a lifetime, and we don't support renewing it
	isSTSRaw, ok := req.Secret.InternalData["is_sts"]
	if ok {
		isSTS, ok := isSTSRaw.(bool)
		if ok {
			if isSTS {
				return nil, nil
			}
		}
	}

	lease, err := b.Lease(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = lease.Lease
	resp.Secret.MaxTTL = lease.LeaseMax
	return resp, nil
}

func secretAccessKeysRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// STS cleans up after itself so we can skip this if is_sts internal data
	// element set to true. If is_sts is not set, assumes old version
	// and defaults to the RAM approach.
	isSTSRaw, ok := req.Secret.InternalData["is_sts"]
	if ok {
		isSTS, ok := isSTSRaw.(bool)
		if ok {
			if isSTS {
				return nil, nil
			}
		} else {
			return nil, fmt.Errorf("secret has is_sts but value could not be understood")
		}
	}

	// Get the username from the internal data
	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, fmt.Errorf("secret is missing username internal data")
	}
	username, ok := usernameRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing username internal data")
	}

	// Use the user rollback mechanism to delete this user
	err := pathUserRollback(ctx, req, "user", map[string]interface{}{
		"username": username,
	})

	return nil, err
}

func normalizeDisplayName(displayName string) string {
	re := regexp.MustCompile("[^a-zA-Z0-9+=,.@_-]")
	return re.ReplaceAllString(displayName, "_")
}
