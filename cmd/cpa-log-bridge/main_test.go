package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestRunHealthcheckReadsBearerFile(t *testing.T) {
	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatal(errListen)
	}
	server := &http.Server{Handler: newBridgeServer(&fakeLogStore{}, testBearerToken).handler()}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	tokenFile := filepath.Join(t.TempDir(), "bearer-token")
	if errWrite := os.WriteFile(tokenFile, []byte(testBearerToken), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	t.Setenv(bearerTokenFileEnv, tokenFile)
	t.Setenv(listenAddressEnv, listener.Addr().String())
	if errHealthcheck := runHealthcheck(); errHealthcheck != nil {
		t.Fatal(errHealthcheck)
	}
}
