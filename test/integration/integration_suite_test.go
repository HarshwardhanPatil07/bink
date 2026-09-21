// SPDX-FileCopyrightText: 2026 The bink Authors
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bootc-dev/bink/test/integration/helpers"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Bink Integration Suite")
}

var _ = SynchronizedBeforeSuite(func() {
	GinkgoWriter.Println("=== Integration Test Suite Setup ===")

	helpers.RequireCommand("podman")
	helpers.RequireBink()

	cmd := helpers.BinkCmd("registry", "start")
	session := helpers.RunCommand(cmd, 2*time.Minute)
	Expect(session.ExitCode()).To(Equal(0), "Failed to start registry: %s", string(session.Err.Contents()))

	GinkgoWriter.Println("✓ All prerequisites verified")
}, func() {})

var _ = SynchronizedAfterSuite(func() {}, func() {
	GinkgoWriter.Println("=== Integration Test Suite Cleanup ===")

	helpers.CleanupAllTestClusters()

	GinkgoWriter.Println("✓ Cleanup complete")
})
