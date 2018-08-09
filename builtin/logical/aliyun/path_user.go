package aliyun

import (
	"context"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

func pathUser(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathUserRead,
		},

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	policyName := d.Get("name").(string)

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

	// Use the helper to create the secret
	return b.secretAccessKeysCreate(ctx, req.Storage, req.DisplayName, result.PolicyType, result.Policy, policyName)
}

func pathUserRollback(ctx context.Context, req *logical.Request, _kind string, data interface{}) error {
	var entry walUser
	if err := mapstructure.Decode(data, &entry); err != nil {
		return err
	}
	username := entry.UserName

	// Get the client
	client, err := clientRAM(ctx, req.Storage)
	if err != nil {
		return err
	}

	// Get information about this user
	listGroupsForUserRequest := ram.CreateListGroupsForUserRequest()
	listGroupsForUserRequest.RpcRequest.Scheme = requests.HTTPS
	listGroupsForUserRequest.UserName = username
	groupsResp, err := client.ListGroupsForUser(listGroupsForUserRequest)
	if err != nil {
		return err
	}
	groups := groupsResp.Groups.Group

	// Policies
	listPoliciesForUserRequest := ram.CreateListPoliciesForUserRequest()
	listPoliciesForUserRequest.RpcRequest.Scheme = requests.HTTPS
	listPoliciesForUserRequest.UserName = username
	policiesResp, err := client.ListPoliciesForUser(listPoliciesForUserRequest)
	if err != nil {
		return err
	}
	policies := policiesResp.Policies.Policy

	listAccessKeysRequest := ram.CreateListAccessKeysRequest()
	listAccessKeysRequest.RpcRequest.Scheme = requests.HTTPS
	listAccessKeysRequest.UserName = username
	keysResp, err := client.ListAccessKeys(listAccessKeysRequest)
	if err != nil {
		return err
	}
	keys := keysResp.AccessKeys.AccessKey

	// Revoke all keys
	deleteAccessKeyRequest := ram.CreateDeleteAccessKeyRequest()
	deleteAccessKeyRequest.RpcRequest.Scheme = requests.HTTPS
	deleteAccessKeyRequest.UserName = username
	for _, k := range keys {
		deleteAccessKeyRequest.UserAccessKeyId = k.AccessKeyId
		_, err = client.DeleteAccessKey(deleteAccessKeyRequest)
		if err != nil {
			return err
		}
	}

	// Detach policies
	detachPolicyFromUserRequest := ram.CreateDetachPolicyFromUserRequest()
	detachPolicyFromUserRequest.RpcRequest.Scheme = requests.HTTPS
	detachPolicyFromUserRequest.UserName = username
	for _, p := range policies {
		detachPolicyFromUserRequest.PolicyType = p.PolicyType
		detachPolicyFromUserRequest.PolicyName = p.PolicyName
		_, err = client.DetachPolicyFromUser(detachPolicyFromUserRequest)
		if err != nil {
			return err
		}
	}

	// Remove the user from all their groups
	removeUserFromGroupRequest := ram.CreateRemoveUserFromGroupRequest()
	removeUserFromGroupRequest.RpcRequest.Scheme = requests.HTTPS
	removeUserFromGroupRequest.UserName = username
	for _, g := range groups {
		removeUserFromGroupRequest.GroupName = g.GroupName
		_, err = client.RemoveUserFromGroup(removeUserFromGroupRequest)
		if err != nil {
			return err
		}
	}

	// Delete the user
	deleteUserRequest := ram.CreateDeleteUserRequest()
	deleteUserRequest.RpcRequest.Scheme = requests.HTTPS
	deleteUserRequest.UserName = username
	_, err = client.DeleteUser(deleteUserRequest)

	return err
}

type walUser struct {
	UserName string
}

const pathUserHelpSyn = `
Generate an access key pair for a specific role.
`

const pathUserHelpDesc = `
This path will generate a new, never before used key pair for
accessing Aliyun. The RAM policy used to back this key pair will be
the "name" parameter. For example, if this backend is mounted at "aliyun",
then "aliyun/creds/deploy" would generate access keys for the "deploy" role.

The access keys will have a lease associated with them. The access keys
can be revoked by using the lease ID.
`
