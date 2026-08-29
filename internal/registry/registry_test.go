// SPDX-FileCopyrightText: 2026 The bink Authors
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/bootc-dev/bink/internal/config"
	. "github.com/onsi/gomega"
	"go.podman.io/podman/v6/pkg/errorhandling"
	"golang.org/x/crypto/bcrypt"
)

func TestIsPodmanNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "not found",
			err: &errorhandling.ErrorModel{
				ResponseCode: http.StatusNotFound,
			},
			want: true,
		},
		{
			name: "wrapped not found",
			err: fmt.Errorf("removing container: %w", &errorhandling.ErrorModel{
				ResponseCode: http.StatusNotFound,
			}),
			want: true,
		},
		{
			name: "conflict",
			err: &errorhandling.ErrorModel{
				ResponseCode: http.StatusConflict,
			},
		},
		{
			name: "unstructured error",
			err:  errors.New("container not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(isPodmanNotFound(tt.err)).To(Equal(tt.want))
		})
	}
}

func TestValidateAuthCredentials(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  string
	}{
		{name: "valid", username: "test-user", password: "test-password"},
		{name: "empty username", password: "test-password", wantErr: "registry username must not be empty"},
		{name: "empty password", username: "test-user", wantErr: "registry password must not be empty"},
		{name: "colon in username", username: "test:user", password: "test-password", wantErr: "registry username must not contain ':', carriage returns, or newlines"},
		{name: "newline in username", username: "test\nuser", password: "test-password", wantErr: "registry username must not contain ':', carriage returns, or newlines"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			err := ValidateAuthCredentials(tt.username, tt.password)
			if tt.wantErr == "" {
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				g.Expect(err).To(MatchError(tt.wantErr))
			}
		})
	}
}

func TestAuthRegistryRequested(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		want     bool
		wantErr  string
	}{
		{name: "no credentials"},
		{name: "both credentials", username: "test-user", password: "test-password", want: true},
		{name: "username only", username: "test-user", wantErr: "registry password must not be empty"},
		{name: "password only", password: "test-password", wantErr: "registry username must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			got, err := AuthRegistryRequested(tt.username, tt.password)
			if tt.wantErr == "" {
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				g.Expect(err).To(MatchError(tt.wantErr))
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestAuthCredentialsMatch(t *testing.T) {
	g := NewWithT(t)
	const (
		username = "test-user"
		password = "test-password"
	)

	_, passwordHash, err := generateHtpasswd(username, password)
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name    string
		labels  map[string]string
		user    string
		pass    string
		want    bool
		wantErr string
	}{
		{
			name: "matching credentials",
			labels: map[string]string{
				config.LabelAuthRegistryUser:         username,
				config.LabelAuthRegistryPasswordHash: passwordHash,
			},
			user: username,
			pass: password,
			want: true,
		},
		{
			name: "different username",
			labels: map[string]string{
				config.LabelAuthRegistryUser:         username,
				config.LabelAuthRegistryPasswordHash: passwordHash,
			},
			user: "other-user",
			pass: password,
		},
		{
			name: "different password",
			labels: map[string]string{
				config.LabelAuthRegistryUser:         username,
				config.LabelAuthRegistryPasswordHash: passwordHash,
			},
			user: username,
			pass: "other-password",
		},
		{
			name: "missing hash",
			labels: map[string]string{
				config.LabelAuthRegistryUser: username,
			},
			user: username,
			pass: password,
		},
		{
			name: "invalid hash",
			labels: map[string]string{
				config.LabelAuthRegistryUser:         username,
				config.LabelAuthRegistryPasswordHash: "invalid",
			},
			user:    username,
			pass:    password,
			wantErr: "verifying stored password hash: crypto/bcrypt: hashedSecret too short to be a bcrypted password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			got, err := authCredentialsMatch(tt.labels, tt.user, tt.pass)
			if tt.wantErr == "" {
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				g.Expect(err).To(MatchError(ContainSubstring(tt.wantErr)))
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestGenerateHtpasswd(t *testing.T) {
	g := NewWithT(t)
	entry, passwordHash, err := generateHtpasswd("test-user", "test-password")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entry).To(Equal("test-user:" + passwordHash))
	g.Expect(bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("test-password"))).To(Succeed())
}
