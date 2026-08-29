// SPDX-FileCopyrightText: 2026 The bink Authors
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/bootc-dev/bink/internal/config"
	"github.com/bootc-dev/bink/internal/podman"
	"github.com/sirupsen/logrus"
	nettypes "go.podman.io/common/libnetwork/types"
	"go.podman.io/podman/v6/libpod/define"
	"go.podman.io/podman/v6/pkg/errorhandling"
	"go.podman.io/podman/v6/pkg/specgen"
	"golang.org/x/crypto/bcrypt"
)

const authHtpasswdEnv = "BINK_AUTH_HTPASSWD"

type Manager struct {
	podman *podman.Client
}

func NewManager() (*Manager, error) {
	client, err := podman.NewClient()
	if err != nil {
		return nil, fmt.Errorf("creating podman client: %w", err)
	}
	return &Manager{podman: client}, nil
}

func (m *Manager) EnsureRegistry(ctx context.Context) error {
	logrus.Info("Ensuring local registry is running")

	if err := m.podman.EnsureImage(ctx, config.RegistryImage); err != nil {
		return fmt.Errorf("ensuring registry image: %w", err)
	}

	if err := m.podman.VolumeCreate(ctx, config.RegistryVolume, nil); err != nil {
		return fmt.Errorf("creating registry volume: %w", err)
	}

	exists, err := m.podman.ContainerExists(ctx, config.RegistryContainerName)
	if err != nil {
		return fmt.Errorf("checking registry container: %w", err)
	}

	if exists {
		return m.ensureExistingRegistry(ctx)
	}

	if err := m.createContainer(ctx); err != nil {
		exists, checkErr := m.podman.ContainerExists(ctx, config.RegistryContainerName)
		if checkErr != nil {
			return errors.Join(err, fmt.Errorf("checking registry after create failure: %w", checkErr))
		}
		if exists {
			logrus.Info("Registry container was created concurrently")
			return m.ensureExistingRegistry(ctx)
		}
		return err
	}

	logrus.Infof("Registry running at %s:%d (host: localhost:%d)",
		config.RegistryStaticIP, config.RegistryPort, config.RegistryPort)
	return nil
}

func (m *Manager) createContainer(ctx context.Context) error {
	opts := &podman.ContainerCreateOptions{
		Name:  config.RegistryContainerName,
		Image: config.RegistryImage,
		NetworkOptions: map[string]nettypes.PerNetworkOptions{
			config.DefaultNetworkName: {
				StaticIPs: []net.IP{net.ParseIP(config.RegistryStaticIP)},
			},
		},
		PortMappings: []nettypes.PortMapping{
			{
				HostPort:      uint16(config.RegistryPort),
				ContainerPort: uint16(config.RegistryPort),
				Protocol:      "tcp",
			},
		},
		Volumes: []*specgen.NamedVolume{
			{
				Name:    config.RegistryVolume,
				Dest:    "/var/lib/registry",
				Options: []string{"z"},
			},
		},
		Environment: map[string]string{
			"REGISTRY_HTTP_SECRET": config.RegistryHTTPSecret,
		},
		Labels: map[string]string{
			config.LabelComponent: "registry",
		},
	}

	_, err := m.podman.ContainerCreate(ctx, opts)
	if err != nil {
		return fmt.Errorf("creating registry container: %w", err)
	}
	return nil
}

func (m *Manager) ensureExistingRegistry(ctx context.Context) error {
	status, err := m.podman.ContainerStatus(ctx, config.RegistryContainerName)
	if err != nil {
		return fmt.Errorf("checking registry status: %w", err)
	}
	if status == define.ContainerStateRunning.String() {
		logrus.Info("Registry already running")
		return nil
	}

	logrus.Infof("Registry container is %s, starting it", status)
	if err := m.podman.ContainerStart(ctx, config.RegistryContainerName); err != nil {
		return fmt.Errorf("starting registry: %w", err)
	}
	logrus.Info("Registry started")
	return nil
}

func (m *Manager) StopRegistry(ctx context.Context) error {
	exists, err := m.podman.ContainerExists(ctx, config.RegistryContainerName)
	if err != nil {
		return fmt.Errorf("checking registry container: %w", err)
	}

	if exists {
		logrus.Info("Stopping registry container")
		if err := m.podman.ContainerStop(ctx, config.RegistryContainerName); err != nil && !isPodmanNotFound(err) {
			logrus.Warnf("Failed to stop registry: %v", err)
		}

		if err := m.podman.ContainerRemove(ctx, config.RegistryContainerName, true); err != nil && !isPodmanNotFound(err) {
			return fmt.Errorf("removing registry container: %w", err)
		}
	} else {
		logrus.Info("Registry container not found")
	}

	volumeExists, err := m.podman.VolumeExists(ctx, config.RegistryVolume)
	if err != nil {
		return fmt.Errorf("checking registry volume: %w", err)
	}
	if volumeExists {
		if err := m.podman.VolumeRemove(ctx, config.RegistryVolume); err != nil && !isPodmanNotFound(err) {
			return fmt.Errorf("removing registry volume: %w", err)
		}
	} else {
		logrus.Info("Registry volume not found")
	}

	logrus.Info("Registry stopped and removed")
	return nil
}

type RegistryStatus struct {
	Running  bool
	IP       string
	HostPort int
	PushURL  string
	PullURL  string
}

func (m *Manager) RegistryInfo(ctx context.Context) (*RegistryStatus, error) {
	info := &RegistryStatus{
		IP:       config.RegistryStaticIP,
		HostPort: config.RegistryPort,
		PushURL:  fmt.Sprintf("localhost:%d", config.RegistryPort),
		PullURL:  fmt.Sprintf("%s.%s:%d", config.RegistryHostname, config.ClusterDomain, config.RegistryPort),
	}

	exists, err := m.podman.ContainerExists(ctx, config.RegistryContainerName)
	if err != nil {
		return info, fmt.Errorf("checking registry container: %w", err)
	}

	if !exists {
		return info, nil
	}

	status, err := m.podman.ContainerStatus(ctx, config.RegistryContainerName)
	if err != nil {
		return info, fmt.Errorf("checking registry status: %w", err)
	}

	info.Running = status == define.ContainerStateRunning.String()
	return info, nil
}

func (m *Manager) EnsureAuthRegistry(ctx context.Context, username, password string) error {
	logrus.Info("Ensuring authenticated registry is running")
	if err := ValidateAuthCredentials(username, password); err != nil {
		return err
	}

	if err := m.podman.EnsureImage(ctx, config.RegistryImage); err != nil {
		return fmt.Errorf("ensuring registry image: %w", err)
	}

	if err := m.podman.VolumeCreate(ctx, config.RegistryVolume, nil); err != nil {
		return fmt.Errorf("creating registry volume: %w", err)
	}

	exists, err := m.podman.ContainerExists(ctx, config.AuthRegistryContainerName)
	if err != nil {
		return fmt.Errorf("checking auth registry container: %w", err)
	}

	if exists {
		return m.ensureExistingAuthRegistry(ctx, username, password)
	}

	if err := m.createAuthContainer(ctx, username, password); err != nil {
		exists, checkErr := m.podman.ContainerExists(ctx, config.AuthRegistryContainerName)
		if checkErr != nil {
			return errors.Join(err, fmt.Errorf("checking auth registry after create failure: %w", checkErr))
		}
		if exists {
			logrus.Info("Auth registry container was created concurrently")
			return m.ensureExistingAuthRegistry(ctx, username, password)
		}
		return err
	}

	logrus.Infof("Authenticated registry running at %s:%d (host: localhost:%d)",
		config.AuthRegistryStaticIP, config.AuthRegistryPort, config.AuthRegistryPort)
	return nil
}

func (m *Manager) createAuthContainer(ctx context.Context, username, password string) error {
	htpasswdEntry, passwordHash, err := generateHtpasswd(username, password)
	if err != nil {
		return fmt.Errorf("generating htpasswd: %w", err)
	}

	opts := &podman.ContainerCreateOptions{
		Name:  config.AuthRegistryContainerName,
		Image: config.RegistryImage,
		Entrypoint: []string{"/bin/sh", "-c",
			`mkdir -p /auth && printf '%s\n' "$` + authHtpasswdEnv + `" > /auth/htpasswd && exec /entrypoint.sh /etc/docker/registry/config.yml`,
		},
		NetworkOptions: map[string]nettypes.PerNetworkOptions{
			config.DefaultNetworkName: {
				StaticIPs: []net.IP{net.ParseIP(config.AuthRegistryStaticIP)},
			},
		},
		PortMappings: []nettypes.PortMapping{
			{
				HostPort:      uint16(config.AuthRegistryPort),
				ContainerPort: uint16(config.AuthRegistryPort),
				Protocol:      "tcp",
			},
		},
		Volumes: []*specgen.NamedVolume{
			{
				Name:    config.RegistryVolume,
				Dest:    "/var/lib/registry",
				Options: []string{"ro", "z"},
			},
		},
		Environment: map[string]string{
			authHtpasswdEnv:                htpasswdEntry,
			"REGISTRY_HTTP_ADDR":           fmt.Sprintf("0.0.0.0:%d", config.AuthRegistryPort),
			"REGISTRY_AUTH":                "htpasswd",
			"REGISTRY_AUTH_HTPASSWD_REALM": "Registry Realm",
			"REGISTRY_AUTH_HTPASSWD_PATH":  "/auth/htpasswd",
			"REGISTRY_HTTP_SECRET":         config.RegistryHTTPSecret,
		},
		Labels: map[string]string{
			config.LabelComponent:                "auth-registry",
			config.LabelAuthRegistryUser:         username,
			config.LabelAuthRegistryPasswordHash: passwordHash,
		},
	}

	_, err = m.podman.ContainerCreate(ctx, opts)
	if err != nil {
		return fmt.Errorf("creating auth registry container: %w", err)
	}
	return nil
}

func (m *Manager) StopAuthRegistry(ctx context.Context) error {
	exists, err := m.podman.ContainerExists(ctx, config.AuthRegistryContainerName)
	if err != nil {
		return fmt.Errorf("checking auth registry container: %w", err)
	}

	if !exists {
		logrus.Info("Auth registry container not found")
		return nil
	}

	logrus.Info("Stopping auth registry container")
	if err := m.podman.ContainerStop(ctx, config.AuthRegistryContainerName); err != nil && !isPodmanNotFound(err) {
		logrus.Warnf("Failed to stop auth registry: %v", err)
	}

	if err := m.podman.ContainerRemove(ctx, config.AuthRegistryContainerName, true); err != nil && !isPodmanNotFound(err) {
		return fmt.Errorf("removing auth registry container: %w", err)
	}

	logrus.Info("Auth registry stopped and removed")
	return nil
}

type AuthRegistryStatus struct {
	Running  bool
	IP       string
	HostPort int
	PullURL  string
	Username string
}

func (m *Manager) AuthRegistryInfo(ctx context.Context) (*AuthRegistryStatus, error) {
	info := &AuthRegistryStatus{
		IP:       config.AuthRegistryStaticIP,
		HostPort: config.AuthRegistryPort,
		PullURL:  fmt.Sprintf("%s.%s:%d", config.AuthRegistryHostname, config.ClusterDomain, config.AuthRegistryPort),
	}

	exists, err := m.podman.ContainerExists(ctx, config.AuthRegistryContainerName)
	if err != nil {
		return info, fmt.Errorf("checking auth registry container: %w", err)
	}

	if !exists {
		return info, nil
	}

	labels, err := m.podman.ContainerLabels(ctx, config.AuthRegistryContainerName)
	if err != nil {
		return info, fmt.Errorf("getting auth registry labels: %w", err)
	}
	if u, ok := labels[config.LabelAuthRegistryUser]; ok {
		info.Username = u
	}

	status, err := m.podman.ContainerStatus(ctx, config.AuthRegistryContainerName)
	if err != nil {
		return info, fmt.Errorf("checking auth registry status: %w", err)
	}

	info.Running = status == define.ContainerStateRunning.String()
	return info, nil
}

func isPodmanNotFound(err error) bool {
	var podmanErr *errorhandling.ErrorModel
	return errors.As(err, &podmanErr) && podmanErr.ResponseCode == http.StatusNotFound
}

func (m *Manager) ensureExistingAuthRegistry(ctx context.Context, username, password string) error {
	labels, err := m.podman.ContainerLabels(ctx, config.AuthRegistryContainerName)
	if err != nil {
		return fmt.Errorf("reading auth registry configuration: %w", err)
	}

	matches, err := authCredentialsMatch(labels, username, password)
	if err != nil {
		return fmt.Errorf("checking auth registry credentials: %w", err)
	}
	if !matches {
		return fmt.Errorf("authenticated registry already exists with different credentials; run 'bink registry stop --auth' before changing them")
	}

	status, err := m.podman.ContainerStatus(ctx, config.AuthRegistryContainerName)
	if err != nil {
		return fmt.Errorf("checking auth registry status: %w", err)
	}
	if status == define.ContainerStateRunning.String() {
		logrus.Info("Authenticated registry already running")
		return nil
	}

	logrus.Infof("Auth registry container is %s, starting it", status)
	if err := m.podman.ContainerStart(ctx, config.AuthRegistryContainerName); err != nil {
		return fmt.Errorf("starting auth registry: %w", err)
	}
	logrus.Info("Authenticated registry started")
	return nil
}

// ValidateAuthCredentials checks that credentials can be represented safely in an htpasswd file.
func ValidateAuthCredentials(username, password string) error {
	if username == "" {
		return fmt.Errorf("registry username must not be empty")
	}
	if strings.ContainsAny(username, ":\r\n") {
		return fmt.Errorf("registry username must not contain ':', carriage returns, or newlines")
	}
	if password == "" {
		return fmt.Errorf("registry password must not be empty")
	}
	return nil
}

// AuthRegistryRequested reports whether credentials request an authenticated registry.
// Supplying only one credential is rejected rather than silently disabling authentication.
func AuthRegistryRequested(username, password string) (bool, error) {
	if username == "" && password == "" {
		return false, nil
	}
	if err := ValidateAuthCredentials(username, password); err != nil {
		return false, err
	}
	return true, nil
}

func authCredentialsMatch(labels map[string]string, username, password string) (bool, error) {
	if labels[config.LabelAuthRegistryUser] != username {
		return false, nil
	}

	passwordHash, ok := labels[config.LabelAuthRegistryPasswordHash]
	if !ok {
		return false, nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, fmt.Errorf("verifying stored password hash: %w", err)
	}
	return true, nil
}

func generateHtpasswd(username, password string) (string, string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hashing password: %w", err)
	}
	return fmt.Sprintf("%s:%s", username, string(hash)), string(hash), nil
}
