// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
)

// Webhooks, the config center and the CDNs used to be target kinds of
// their own, which meant a deployment could do exactly one of them. Real
// deployments are sequences — write the file, push to the config center,
// poke a reload endpoint, check the result — so they are steps now, and a
// target is always a pipeline.
//
// The implementations are reused unchanged: each already builds from a
// JSON config and returns events plus an error, which is what a step
// needs. Adapting rather than rewriting keeps their tests meaningful.
func stepFromTarget(
	stepType string,
	build func(configJSON string, opts Options) (Target, error),
) func(context.Context, *pipelineState, json.RawMessage) error {

	return func(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
		target, err := build(string(raw), st.opts)
		if err != nil {
			return fmt.Errorf("%s: %w", stepType, err)
		}
		events, deployErr := target.Deploy(ctx, st.cert)
		// The events describe what happened either way, so they are
		// recorded before the error is considered.
		for _, e := range events {
			st.emit(e)
		}
		if deployErr != nil {
			return fmt.Errorf("%s: %w", stepType, deployErr)
		}
		return nil
	}
}

var (
	stepWebhook = stepFromTarget(StepWebhook,
		func(cfg string, _ Options) (Target, error) { return newWebhook(cfg) })

	stepConfigCenter = stepFromTarget(StepConfigCenter,
		func(cfg string, o Options) (Target, error) { return newConfigCenter(cfg, o.ManagementURL) })

	stepAliyunCDN = stepFromTarget(StepAliyunCDN,
		func(cfg string, _ Options) (Target, error) { return newAliyunCDN(cfg) })

	stepTencentCDN = stepFromTarget(StepTencentCDN,
		func(cfg string, _ Options) (Target, error) { return newTencentCDN(cfg) })
)
