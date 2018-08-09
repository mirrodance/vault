package aliyun

import (
	"context"

	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
)

func getRootConfig(ctx context.Context, s logical.Storage) (*config, error) {
	credsConfig := &config{}
	entry, err := s.Get(ctx, "config/root")
	if err != nil {
		return nil, err
	}
	if entry != nil {
		var config rootConfig
		if err := entry.DecodeJSON(&config); err != nil {
			return nil, errwrap.Wrapf("error reading root configuration: {{err}}", err)
		}

		credsConfig.accessKeyID = config.AccessKey
		credsConfig.accessKeySecret = config.SecretKey
		credsConfig.regionID = config.Region
	}

	if credsConfig.regionID == "" {
		credsConfig.regionID = os.Getenv("ALIYUN_REGION")
		if credsConfig.regionID == "" {
			credsConfig.regionID = os.Getenv("ALIYUN_DEFAULT_REGION")
			if credsConfig.regionID == "" {
				credsConfig.regionID = "cn-hangzhou"
			}
		}
	}

	return credsConfig, nil
}

func clientRAM(ctx context.Context, s logical.Storage) (*ram.Client, error) {
	aliyunConfig, err := getRootConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	return ram.NewClientWithAccessKey(
		aliyunConfig.regionID, aliyunConfig.accessKeyID, aliyunConfig.accessKeySecret)
}

func clientSTS(ctx context.Context, s logical.Storage) (*sts.Client, error) {
	aliyunConfig, err := getRootConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	return sts.NewClientWithAccessKey(
		aliyunConfig.regionID, aliyunConfig.accessKeyID, aliyunConfig.accessKeySecret)
}

type config struct {
	regionID        string
	accessKeyID     string
	accessKeySecret string
}
