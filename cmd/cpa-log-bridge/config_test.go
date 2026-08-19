package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"CPA_LOG_BRIDGE_DATABASE_URL",
		"CPA_LOG_BRIDGE_BEARER_TOKEN",
		databaseURLFileEnv,
		bearerTokenFileEnv,
		listenAddressEnv,
	} {
		t.Setenv(key, "")
	}
}

func TestLoadConfigFromSecretFiles(t *testing.T) {
	clearConfigEnvironment(t)
	directory := t.TempDir()
	databaseFile := filepath.Join(directory, "database-url")
	tokenFile := filepath.Join(directory, "bearer-token")
	if errWrite := os.WriteFile(databaseFile, []byte("postgres://reader@example/new-api\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	token := strings.Repeat("a", 48)
	if errWrite := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	t.Setenv(databaseURLFileEnv, databaseFile)
	t.Setenv(bearerTokenFileEnv, tokenFile)

	config, errConfig := loadConfig()
	if errConfig != nil {
		t.Fatal(errConfig)
	}
	if config.DatabaseURL != "postgres://reader@example/new-api" || config.BearerToken != token {
		t.Fatalf("unexpected config: %#v", config)
	}
	if config.ListenAddress != defaultListenAddress {
		t.Fatalf("listen address = %q, want %q", config.ListenAddress, defaultListenAddress)
	}
}

func TestLoadConfigRejectsEnvironmentSecretsAndWeakTokens(t *testing.T) {
	t.Run("direct secret", func(t *testing.T) {
		clearConfigEnvironment(t)
		t.Setenv("CPA_LOG_BRIDGE_DATABASE_URL", "postgres://direct")
		if _, errConfig := loadConfig(); errConfig == nil {
			t.Fatal("expected direct environment secret to fail")
		}
	})
	t.Run("short bearer", func(t *testing.T) {
		clearConfigEnvironment(t)
		directory := t.TempDir()
		databaseFile := filepath.Join(directory, "database-url")
		tokenFile := filepath.Join(directory, "bearer-token")
		if errWrite := os.WriteFile(databaseFile, []byte("postgres://reader"), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		if errWrite := os.WriteFile(tokenFile, []byte("short"), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		t.Setenv(databaseURLFileEnv, databaseFile)
		t.Setenv(bearerTokenFileEnv, tokenFile)
		if _, errConfig := loadConfig(); errConfig == nil {
			t.Fatal("expected short bearer token to fail")
		}
	})
	t.Run("bearer whitespace", func(t *testing.T) {
		clearConfigEnvironment(t)
		directory := t.TempDir()
		databaseFile := filepath.Join(directory, "database-url")
		tokenFile := filepath.Join(directory, "bearer-token")
		if errWrite := os.WriteFile(databaseFile, []byte("postgres://reader"), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		if errWrite := os.WriteFile(tokenFile, []byte(strings.Repeat("c", 32)+" bad"), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		t.Setenv(databaseURLFileEnv, databaseFile)
		t.Setenv(bearerTokenFileEnv, tokenFile)
		if _, errConfig := loadConfig(); errConfig == nil {
			t.Fatal("expected bearer token containing whitespace to fail")
		}
	})
}
