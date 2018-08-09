package aliyun

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},

			"policy_type": {
				Type:        framework.TypeString,
				Description: "RAM policy type, System or Custom",
			},

			"policy": {
				Type:        framework.TypeString,
				Description: "Name of the policy",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: pathRolesDelete,
			logical.ReadOperation:   pathRolesRead,
			logical.UpdateOperation: pathRolesWrite,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "policy/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "policy/"+d.Get("name").(string))
	return nil, err
}

func pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "policy/"+d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	val := string(entry.Value)
	return &logical.Response{
		Data: map[string]interface{}{
			"policy": val,
		},
	}, nil
}

func pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	v := roleConfig{
		Policy:     d.Get("policy").(string),
		PolicyType: d.Get("policy_type").(string),
	}
	entry, err := logical.StorageEntryJSON("policy/"+d.Get("name").(string), v)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type roleConfig struct {
	Policy     string `json:"policy"`
	PolicyType string `json:"policy_type"`
}

const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRolesHelpSyn = `
Read, write and reference RAM policies that access keys can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create access keys. These roles are associated with RAM policies that
map directly to the route to read the access keys. For example, if the
backend is mounted at "aliyun" and you create a role at "aliyun/roles/deploy"
then a user could request access credentials at "aliyun/creds/deploy".

To validate the keys, attempt to read an access key after writing the policy.
`
