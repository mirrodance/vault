package aliyun

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfigRoot() *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access key with permission to create new keys.",
			},

			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret key with permission to create new keys.",
			},

			"region": {
				Type:        framework.TypeString,
				Description: "Region for API calls.",
			},
			"max_retries": {
				Type:        framework.TypeInt,
				Description: "Maximum number of retries for recoverable exceptions of Aliyun APIs",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: pathConfigRootWrite,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func pathConfigRootWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := logical.StorageEntryJSON("config/root", rootConfig{
		AccessKey:  data.Get("access_key").(string),
		SecretKey:  data.Get("secret_key").(string),
		Region:     data.Get("region").(string),
		MaxRetries: data.Get("max_retries").(int),
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type rootConfig struct {
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
	Region     string `json:"region"`
	MaxRetries int    `json:"max_retries"`
}

const pathConfigRootHelpSyn = `
Configure the root credentials that are used to manage RAM.
`

const pathConfigRootHelpDesc = `
Before doing anything, the Aliyun backend needs credentials that are able
to manage RAM roles, users, access keys, etc. This endpoint is used
to configure those credentials. They don't necessarily need to be root
keys as long as they have permission to manage RAM.
`
