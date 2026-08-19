package main

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

const (
	databaseURLFileEnv   = "CPA_LOG_BRIDGE_DATABASE_URL_FILE"
	bearerTokenFileEnv   = "CPA_LOG_BRIDGE_BEARER_TOKEN_FILE"
	listenAddressEnv     = "CPA_LOG_BRIDGE_LISTEN_ADDR"
	defaultListenAddress = ":8080"
)

type bridgeConfig struct {
	ListenAddress string
	DatabaseURL   string
	BearerToken   string
}

func loadConfig() (bridgeConfig, error) {
	for _, forbidden := range []string{"CPA_LOG_BRIDGE_DATABASE_URL", "CPA_LOG_BRIDGE_BEARER_TOKEN"} {
		if strings.TrimSpace(os.Getenv(forbidden)) != "" {
			return bridgeConfig{}, fmt.Errorf("%s is not supported; use the corresponding _FILE setting", forbidden)
		}
	}
	databaseURL, errDatabase := secretFile(databaseURLFileEnv)
	if errDatabase != nil {
		return bridgeConfig{}, errDatabase
	}
	if databaseURL == "" {
		return bridgeConfig{}, fmt.Errorf("%s is required", databaseURLFileEnv)
	}
	bearerToken, errToken := loadBearerToken()
	if errToken != nil {
		return bridgeConfig{}, errToken
	}
	listenAddress := strings.TrimSpace(os.Getenv(listenAddressEnv))
	if listenAddress == "" {
		listenAddress = defaultListenAddress
	}
	return bridgeConfig{
		ListenAddress: listenAddress,
		DatabaseURL:   databaseURL,
		BearerToken:   bearerToken,
	}, nil
}

func loadBearerToken() (string, error) {
	bearerToken, errToken := secretFile(bearerTokenFileEnv)
	if errToken != nil {
		return "", errToken
	}
	if len(bearerToken) < 32 || len(bearerToken) > 512 {
		return "", fmt.Errorf("bearer token must contain 32-512 characters")
	}
	if strings.IndexFunc(bearerToken, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("bearer token cannot contain whitespace")
	}
	return bearerToken, nil
}

func secretFile(fileEnv string) (string, error) {
	path := strings.TrimSpace(os.Getenv(fileEnv))
	if path == "" {
		return "", fmt.Errorf("%s is required", fileEnv)
	}
	content, errRead := os.ReadFile(path)
	if errRead != nil {
		return "", fmt.Errorf("read %s: %w", fileEnv, errRead)
	}
	return strings.TrimSpace(string(content)), nil
}
