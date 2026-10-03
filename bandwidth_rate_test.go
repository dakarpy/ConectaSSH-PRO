package main

import (
	"testing"
	"time"
)

func TestBandwidthSamplerFirstObservationIsBaselineOnly(t *testing.T) {
	s := newBandwidthSampler(0, time.Minute)
	now := time.Now()
	s.Observe("bob", 10_000, 20_000, now)
	rate, ok := s.Rate("bob")
	if !ok {
		t.Fatal("expected the account to be tracked after the first observation")
	}
	if !rate.isZero() {
		t.Fatalf("first observation must not report a speed, got %+v", rate)
	}
}

func TestBandwidthSamplerComputesBytesPerSecond(t *testing.T) {
	s := newBandwidthSampler(0, time.Minute) // no smoothing: exact delta/dt
	now := time.Now()
	s.Observe("bob", 0, 0, now)
	// 2 MB up and 10 MB down over 2 seconds.
	s.Observe("bob", 2<<20, 10<<20, now.Add(2*time.Second))
	rate, _ := s.Rate("bob")
	if wantUp := float64(1 << 20); rate.UpBytesPerSec != wantUp {
		t.Fatalf("up = %v, want %v", rate.UpBytesPerSec, wantUp)
	}
	if wantDown := float64(5 << 20); rate.DownBytesPerSec != wantDown {
		t.Fatalf("down = %v, want %v", rate.DownBytesPerSec, wantDown)
	}
}

func TestBandwidthSamplerIgnoresSamplesTakenTooCloseTogether(t *testing.T) {
	s := newBandwidthSampler(0, time.Minute)
	now := time.Now()
	s.Observe("bob", 0, 0, now)
	s.Observe("bob", 5<<20, 5<<20, now.Add(10*time.Millisecond))
	rate, _ := s.Rate("bob")
	if !rate.isZero() {
		t.Fatalf("a 10ms interval must not produce a speed, got %+v", rate)
	}
}

func TestBandwidthSamplerRebaselinesAfterTrafficReset(t *testing.T) {
	s := newBandwidthSampler(0, time.Minute)
	now := time.Now()
	s.Observe("bob", 0, 0, now)
	s.Observe("bob", 4<<20, 4<<20, now.Add(2*time.Second))
	// Panel reset the account's traffic: counters go back to zero.
	s.Observe("bob", 0, 0, now.Add(4*time.Second))
	rate, _ := s.Rate("bob")
	if !rate.isZero() {
		t.Fatalf("counters moving backwards must reset the speed, got %+v", rate)
	}
	s.Observe("bob", 2<<20, 0, now.Add(6*time.Second))
	rate, _ = s.Rate("bob")
	if wantUp := float64(1 << 20); rate.UpBytesPerSec != wantUp {
		t.Fatalf("up after reset = %v, want %v", rate.UpBytesPerSec, wantUp)
	}
}

func TestBandwidthSamplerReportsZeroWhenIdle(t *testing.T) {
	s := newBandwidthSampler(0, time.Minute)
	now := time.Now()
	s.Observe("bob", 0, 0, now)
	s.Observe("bob", 4<<20, 4<<20, now.Add(2*time.Second))
	s.Observe("bob", 4<<20, 4<<20, now.Add(4*time.Second))
	rate, _ := s.Rate("bob")
	if !rate.isZero() {
		t.Fatalf("unchanged counters must report an idle account, got %+v", rate)
	}
}

func TestBandwidthSamplerDropsStaleSpeeds(t *testing.T) {
	s := newBandwidthSampler(0, time.Second)
	now := time.Now().Add(-time.Hour)
	s.Observe("bob", 0, 0, now)
	s.Observe("bob", 4<<20, 4<<20, now.Add(2*time.Second))
	rate, ok := s.Rate("bob")
	if !ok {
		t.Fatal("expected the account to still be tracked")
	}
	if !rate.isZero() {
		t.Fatalf("an hour-old sample must not still report a speed, got %+v", rate)
	}
}

func TestBandwidthSamplerSmoothsWithTimeConstant(t *testing.T) {
	s := newBandwidthSampler(5*time.Second, time.Minute)
	now := time.Now()
	s.Observe("bob", 0, 0, now)
	// First real sample has no previous rate to blend with, so it lands exactly.
	s.Observe("bob", 2<<20, 0, now.Add(2*time.Second))
	first, _ := s.Rate("bob")
	if first.UpBytesPerSec != float64(1<<20) {
		t.Fatalf("first speed = %v, want %v", first.UpBytesPerSec, float64(1<<20))
	}
	// Traffic stops: the smoothed value has to fall without jumping to zero.
	s.Observe("bob", 2<<20, 0, now.Add(4*time.Second))
	second, _ := s.Rate("bob")
	if second.UpBytesPerSec <= 0 || second.UpBytesPerSec >= first.UpBytesPerSec {
		t.Fatalf("smoothed speed = %v, want a value between 0 and %v", second.UpBytesPerSec, first.UpBytesPerSec)
	}
}

func TestBandwidthSamplerRateForKeysAndRetain(t *testing.T) {
	s := newBandwidthSampler(0, time.Minute)
	now := time.Now()
	s.Observe("uuid-1", 0, 0, now)
	s.Observe("uuid-1", 1<<20, 0, now.Add(1*time.Second))
	if _, ok := s.RateForKeys("", "unknown@example", "uuid-1"); !ok {
		t.Fatal("RateForKeys must find the client under any of its identifiers")
	}
	s.Retain(map[string]struct{}{"uuid-2": {}})
	if _, ok := s.Rate("uuid-1"); ok {
		t.Fatal("Retain must drop accounts that no longer exist")
	}
}
