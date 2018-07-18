package alibaba

import (
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-auth-alibaba/tools"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
)

type alibabaMethod struct {
	logger        hclog.Logger
	mountPath     string
	accessKey     string
	secretKey     string
	securityToken string
	region        string
}

func NewAlibabaAuthMethod(conf *auth.AuthConfig) (auth.AuthMethod, error) {
	if conf == nil {
		return nil, errors.New("empty config")
	}
	if conf.Config == nil {
		return nil, errors.New("empty config data")
	}

	a := &alibabaMethod{
		logger:    conf.Logger,
		mountPath: conf.MountPath,
	}

	accessKeyRaw, ok := conf.Config["access_key"]
	if ok {
		a.accessKey, ok = accessKeyRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'access_key' value into string")
		}
	}

	secretKeyRaw, ok := conf.Config["secret_key"]
	if ok {
		a.secretKey, ok = secretKeyRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'secret_key' value into string")
		}
	}

	securityTokenRaw, ok := conf.Config["security_token"]
	if ok {
		a.securityToken, ok = securityTokenRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'security_token' value into string")
		}
	}

	regionRaw, ok := conf.Config["region"]
	if ok {
		a.region, ok = regionRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'region' value into string")
		}
	}

	return a, nil
}

func (a *alibabaMethod) Authenticate(client *api.Client) (*api.Secret, error) {
	a.logger.Trace("beginning authentication")

	data, err := tools.GenerateLoginData(a.accessKey, a.secretKey, a.securityToken, a.region)
	if err != nil {
		return nil, errwrap.Wrapf("error creating login value: {{err}}", err)
	}

	secret, err := client.Logical().Write(fmt.Sprintf("%s/login", a.mountPath), data)
	if err != nil {
		return nil, errwrap.Wrapf("error logging in: {{err}}", err)
	}

	return secret, nil
}

func (a *alibabaMethod) NewCreds() chan struct{} {
	return nil
}

func (a *alibabaMethod) Shutdown() {
}
