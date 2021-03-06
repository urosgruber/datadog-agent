// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// Package sampler contains all the logic of the agent-side trace sampling
//
// Currently implementation is based on the scoring of the "signature" of each trace
// Based on the score, we get a sample rate to apply to the given trace
//
// Current score implementation is super-simple, it is a counter with polynomial decay per signature.
// We increment it for each incoming trace then we periodically divide the score by two every X seconds.
// Right after the division, the score is an approximation of the number of received signatures over X seconds.
// It is different from the scoring in the Agent.
//
// Since the sampling can happen at different levels (client, agent, server) or depending on different rules,
// we have to track the sample rate applied at previous steps. This way, sampling twice at 50% can result in an
// effective 25% sampling. The rate is stored as a metric in the trace root.
package sampler

import (
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/trace/pb"
)

const (
	deprecatedRateKey = "_sampling_priority_rate_v1"
	agentRateKey      = "_dd.agent_psr"
	ruleRateKey       = "_dd.rule_psr"
	syncPeriod        = 3 * time.Second
	// prioritySamplingRateThresholdTo1 defines the maximum allowed sampling rate below 1.
	// If this is surpassed, the rate is set to 1.
	prioritySamplingRateThresholdTo1 = 0.3
)

// PriorityEngine is the main component of the sampling logic
type PriorityEngine struct {
	// Sampler is the underlying sampler used by this engine, sharing logic among various engines.
	Sampler *Sampler

	rateByService *RateByService
	catalog       *serviceKeyCatalog
	exit          chan struct{}
}

// NewPriorityEngine returns an initialized Sampler
func NewPriorityEngine(extraRate float64, targetTPS float64, rateByService *RateByService) *PriorityEngine {
	s := &PriorityEngine{
		Sampler:       newSampler(extraRate, targetTPS),
		rateByService: rateByService,
		catalog:       newServiceLookup(),
		exit:          make(chan struct{}),
	}
	s.Sampler.setRateThresholdTo1(prioritySamplingRateThresholdTo1)

	return s
}

// Run runs and block on the Sampler main loop
func (s *PriorityEngine) Run() {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		s.Sampler.Run()
		wg.Done()
	}()

	go func() {
		t := time.NewTicker(syncPeriod)
		defer t.Stop()

		for {
			select {
			case <-t.C:
				s.rateByService.SetAll(s.ratesByService())
			case <-s.exit:
				wg.Done()
				return
			}
		}
	}()

	wg.Wait()
}

// Stop stops the main Run loop
func (s *PriorityEngine) Stop() {
	s.Sampler.Stop()
	close(s.exit)
}

// Sample counts an incoming trace and returns the trace sampling decision and the applied sampling rate
func (s *PriorityEngine) Sample(trace pb.Trace, root *pb.Span, env string) bool {
	// Extra safety, just in case one trace is empty
	if len(trace) == 0 {
		return false
	}

	samplingPriority, _ := GetSamplingPriority(root)

	// Regardless of rates, sampling here is based on the metadata set
	// by the client library. Which, is turn, is based on agent hints,
	// but the rule of thumb is: respect client choice.
	sampled := samplingPriority > 0

	// Short-circuit and return without counting the trace in the sampling rate logic
	// if its value has not been set automaticallt by the client lib.
	// The feedback loop should be scoped to the values it can act upon.
	if samplingPriority < 0 {
		return sampled
	}
	if samplingPriority > 1 {
		return sampled
	}

	signature := s.catalog.register(ServiceSignature{root.Service, env})

	// Update sampler state by counting this trace
	s.Sampler.Backend.CountSignature(signature)

	if sampled {
		s.applyRate(sampled, root, signature)
		s.Sampler.Backend.CountSample()
	}
	return sampled
}

func (s *PriorityEngine) applyRate(sampled bool, root *pb.Span, signature Signature) {
	if root.ParentID != 0 {
		return
	}
	// recent tracers annotate roots with applied priority rate
	// agentRateKey is set when the agent computed rate is applied
	if _, ok := getMetric(root, agentRateKey); ok {
		return
	}
	// ruleRateKey is set when a tracer rule rate is applied
	if _, ok := getMetric(root, ruleRateKey); ok {
		return
	}

	// slow path used by older tracer versions
	// dd-trace-go used to set the rate in deprecatedRateKey
	if _, ok := getMetric(root, deprecatedRateKey); !ok {
		// if it's not set add next rate
		rate := s.Sampler.GetSignatureSampleRate(signature)
		if rate > prioritySamplingRateThresholdTo1 {
			rate = 1
		}
		setMetric(root, deprecatedRateKey, rate)
	}
}

// GetState collects and return internal statistics and coefficients for indication purposes
// It returns an interface{}, as other samplers might return other informations.
func (s *PriorityEngine) GetState() interface{} {
	return s.Sampler.GetState()
}

// ratesByService returns all rates by service, this information is useful for
// agents to pick the right service rate.
func (s *PriorityEngine) ratesByService() map[ServiceSignature]float64 {
	return s.catalog.ratesByService(s.Sampler.GetAllSignatureSampleRates(), s.Sampler.GetDefaultSampleRate())
}

// GetType return the type of the sampler engine
func (s *PriorityEngine) GetType() EngineType {
	return PriorityEngineType
}
