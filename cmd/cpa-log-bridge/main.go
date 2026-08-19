package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if errHealthcheck := runHealthcheck(); errHealthcheck != nil {
			log.WithError(errHealthcheck).Error("CPA log bridge health check failed")
			os.Exit(1)
		}
		return
	}
	if errRun := run(); errRun != nil {
		log.WithError(errRun).Error("CPA log bridge stopped")
		os.Exit(1)
	}
}

func runHealthcheck() error {
	bearerToken, errToken := loadBearerToken()
	if errToken != nil {
		return errToken
	}
	listenAddress := os.Getenv(listenAddressEnv)
	if listenAddress == "" {
		listenAddress = defaultListenAddress
	}
	_, port, errSplit := net.SplitHostPort(listenAddress)
	if errSplit != nil {
		return fmt.Errorf("parse listen address: %w", errSplit)
	}
	request, errRequest := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", port)+"/healthz", nil)
	if errRequest != nil {
		return fmt.Errorf("create health request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+bearerToken)
	client := &http.Client{Timeout: 5 * time.Second}
	response, errDo := client.Do(request)
	if errDo != nil {
		return fmt.Errorf("request health endpoint: %w", errDo)
	}
	defer func() {
		if errClose := response.Body.Close(); errClose != nil {
			log.WithError(errClose).Warn("failed to close health response")
		}
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned status %d", response.StatusCode)
	}
	return nil
}

func run() error {
	config, errConfig := loadConfig()
	if errConfig != nil {
		return fmt.Errorf("load configuration: %w", errConfig)
	}
	store, errStore := newPostgresStore(config.DatabaseURL)
	if errStore != nil {
		return errStore
	}
	defer func() {
		if errClose := store.Close(); errClose != nil {
			log.WithError(errClose).Warn("failed to close log bridge store")
		}
	}()

	startupContext, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	errHealth := store.Health(startupContext)
	cancelStartup()
	if errHealth != nil {
		return fmt.Errorf("check postgres at startup: %w", errHealth)
	}

	server := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           newBridgeServer(store, config.BearerToken).handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errServer := make(chan error, 1)
	go func() {
		log.WithField("address", config.ListenAddress).Info("CPA log bridge listening")
		if errListen := server.ListenAndServe(); errListen != nil && !errors.Is(errListen, http.ErrServerClosed) {
			errServer <- errListen
			return
		}
		errServer <- nil
	}()

	signalContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	select {
	case errListen := <-errServer:
		if errListen != nil {
			return fmt.Errorf("serve HTTP: %w", errListen)
		}
		return nil
	case <-signalContext.Done():
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if errShutdown := server.Shutdown(shutdownContext); errShutdown != nil {
		return fmt.Errorf("shut down HTTP server: %w", errShutdown)
	}
	if errListen := <-errServer; errListen != nil {
		return fmt.Errorf("serve HTTP: %w", errListen)
	}
	return nil
}
