package core

import (
	"errors"
	"os"
	"strings"

	"azugo.io/azugo"
	"azugo.io/core/validation"
	"gopkg.in/yaml.v3"
)

type AuthProviderStoreFile struct {
	config    AuthProviderStoreFileConfig
	providers map[string]*AuthProviderConfig
}

type AuthProviderStoreFileConfig struct {
	Path string `mapstructure:"path" validate:"required"`
}

func NewFileAuthProviderStore(app *azugo.App, config AuthProviderStoreFileConfig) (*AuthProviderStoreFile, error) {
	if config.Path == "" {
		return nil, errors.New("auth file store path is required")
	}

	var providers []*AuthProviderConfig

	yamlFile, err := os.ReadFile(config.Path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, &providers)
	if err != nil {
		return nil, err
	}

	validator := validation.New()

	providersMap := make(map[string]*AuthProviderConfig)
	for _, provider := range providers {
		err = validator.Struct(provider)
		if err != nil {
			return nil, err
		}
		providersMap[provider.ID] = provider
	}

	return &AuthProviderStoreFile{config, providersMap}, nil
}

func (s *AuthProviderStoreFile) GetAvailableProviders(clientID string) ([]*AuthProviderConfig, error) {
	providers := make([]*AuthProviderConfig, 0, len(s.providers))
	for _, provider := range s.providers {
		providers = append(providers, provider)
	}
	return providers, nil
}

func (s *AuthProviderStoreFile) GetProvider(id string) (*AuthProviderConfig, error) {
	for _, provider := range s.providers {
		if strings.EqualFold(provider.ID, id) {
			return provider, nil
		}
	}

	return nil, errors.New("provider not found")
}

func (s *AuthProviderStoreFile) GetAllProviders() ([]*AuthProviderConfig, error) {
	providers := make([]*AuthProviderConfig, 0, len(s.providers))
	for _, provider := range s.providers {
		providers = append(providers, provider)
	}

	return providers, nil
}
