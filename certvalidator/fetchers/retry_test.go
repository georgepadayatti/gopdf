package fetchers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", config.MaxAttempts)
	}
	if config.InitialDelay != 1*time.Second {
		t.Errorf("InitialDelay = %v, want 1s", config.InitialDelay)
	}
	if config.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay = %v, want 30s", config.MaxDelay)
	}
	if config.Multiplier != 2.0 {
		t.Errorf("Multiplier = %f, want 2.0", config.Multiplier)
	}
	if config.Jitter != 0.1 {
		t.Errorf("Jitter = %f, want 0.1", config.Jitter)
	}
}

func TestAggressiveRetryConfig(t *testing.T) {
	config := AggressiveRetryConfig()

	if config.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d, want 5", config.MaxAttempts)
	}
	if config.InitialDelay != 500*time.Millisecond {
		t.Errorf("InitialDelay = %v, want 500ms", config.InitialDelay)
	}
}

func TestConservativeRetryConfig(t *testing.T) {
	config := ConservativeRetryConfig()

	if config.MaxAttempts != 2 {
		t.Errorf("MaxAttempts = %d, want 2", config.MaxAttempts)
	}
	if config.InitialDelay != 2*time.Second {
		t.Errorf("InitialDelay = %v, want 2s", config.InitialDelay)
	}
}

func TestRetryConfigCalculateDelay(t *testing.T) {
	config := &RetryConfig{
		InitialDelay: 1 * time.Second,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       0, // No jitter for predictable tests
	}

	tests := []struct {
		attempt  int
		wantMin  time.Duration
		wantMax  time.Duration
	}{
		{0, 0, 0},
		{1, 1 * time.Second, 1 * time.Second},
		{2, 2 * time.Second, 2 * time.Second},
		{3, 4 * time.Second, 4 * time.Second},
		{4, 8 * time.Second, 8 * time.Second},
		{5, 10 * time.Second, 10 * time.Second}, // Capped at MaxDelay
		{6, 10 * time.Second, 10 * time.Second}, // Still capped
	}

	for _, tt := range tests {
		delay := config.calculateDelay(tt.attempt)
		if delay < tt.wantMin || delay > tt.wantMax {
			t.Errorf("calculateDelay(%d) = %v, want between %v and %v",
				tt.attempt, delay, tt.wantMin, tt.wantMax)
		}
	}
}

func TestRetryConfigCalculateDelayWithJitter(t *testing.T) {
	config := &RetryConfig{
		InitialDelay: 1 * time.Second,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.5, // 50% jitter
	}

	// With 50% jitter, delay for attempt 1 should be between 0.5s and 1.5s
	for i := 0; i < 10; i++ {
		delay := config.calculateDelay(1)
		minExpected := 500 * time.Millisecond
		maxExpected := 1500 * time.Millisecond
		if delay < minExpected || delay > maxExpected {
			t.Errorf("calculateDelay(1) with jitter = %v, want between %v and %v",
				delay, minExpected, maxExpected)
		}
	}
}

func TestRetryConfigIsRetryable(t *testing.T) {
	customErr := errors.New("custom error")

	t.Run("AllErrorsRetryable", func(t *testing.T) {
		config := &RetryConfig{}
		if !config.isRetryable(customErr) {
			t.Error("Expected custom error to be retryable")
		}
	})

	t.Run("ContextCanceledNotRetryable", func(t *testing.T) {
		config := &RetryConfig{}
		if config.isRetryable(context.Canceled) {
			t.Error("Expected context.Canceled to not be retryable")
		}
	})

	t.Run("ContextDeadlineNotRetryable", func(t *testing.T) {
		config := &RetryConfig{}
		if config.isRetryable(context.DeadlineExceeded) {
			t.Error("Expected context.DeadlineExceeded to not be retryable")
		}
	})

	t.Run("SpecificRetryableErrors", func(t *testing.T) {
		config := &RetryConfig{
			RetryableErrors: []error{customErr},
		}
		if !config.isRetryable(customErr) {
			t.Error("Expected custom error to be retryable")
		}
		if config.isRetryable(errors.New("other error")) {
			t.Error("Expected other error to not be retryable")
		}
	})
}

func TestRetry(t *testing.T) {
	t.Run("SuccessOnFirstAttempt", func(t *testing.T) {
		config := DefaultRetryConfig()
		var attempts int32

		result, retryResult := Retry(context.Background(), config, func(ctx context.Context) (string, error) {
			atomic.AddInt32(&attempts, 1)
			return "success", nil
		})

		if result != "success" {
			t.Errorf("Result = %q, want %q", result, "success")
		}
		if !retryResult.Success {
			t.Error("Expected success")
		}
		if retryResult.Attempts != 1 {
			t.Errorf("Attempts = %d, want 1", retryResult.Attempts)
		}
		if attempts != 1 {
			t.Errorf("Function called %d times, want 1", attempts)
		}
	})

	t.Run("SuccessOnRetry", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  3,
			InitialDelay: 1 * time.Millisecond,
			MaxDelay:     10 * time.Millisecond,
			Multiplier:   2.0,
		}
		var attempts int32

		result, retryResult := Retry(context.Background(), config, func(ctx context.Context) (string, error) {
			n := atomic.AddInt32(&attempts, 1)
			if n < 3 {
				return "", errors.New("temporary error")
			}
			return "success", nil
		})

		if result != "success" {
			t.Errorf("Result = %q, want %q", result, "success")
		}
		if !retryResult.Success {
			t.Error("Expected success")
		}
		if retryResult.Attempts != 3 {
			t.Errorf("Attempts = %d, want 3", retryResult.Attempts)
		}
	})

	t.Run("AllAttemptsFail", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  3,
			InitialDelay: 1 * time.Millisecond,
			MaxDelay:     10 * time.Millisecond,
			Multiplier:   2.0,
		}
		var attempts int32

		result, retryResult := Retry(context.Background(), config, func(ctx context.Context) (string, error) {
			atomic.AddInt32(&attempts, 1)
			return "", errors.New("persistent error")
		})

		if result != "" {
			t.Errorf("Result = %q, want empty", result)
		}
		if retryResult.Success {
			t.Error("Expected failure")
		}
		if retryResult.Attempts != 3 {
			t.Errorf("Attempts = %d, want 3", retryResult.Attempts)
		}
		if len(retryResult.Errors) != 3 {
			t.Errorf("Errors count = %d, want 3", len(retryResult.Errors))
		}
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  5,
			InitialDelay: 100 * time.Millisecond,
			MaxDelay:     1 * time.Second,
			Multiplier:   2.0,
		}

		ctx, cancel := context.WithCancel(context.Background())
		var attempts int32

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		_, retryResult := Retry(ctx, config, func(ctx context.Context) (string, error) {
			atomic.AddInt32(&attempts, 1)
			return "", errors.New("error")
		})

		if retryResult.Success {
			t.Error("Expected failure due to cancellation")
		}
		// Should have stopped early due to context cancellation
		if attempts >= 5 {
			t.Errorf("Should have stopped early, got %d attempts", attempts)
		}
	})
}

func TestRetryMultiURL(t *testing.T) {
	t.Run("FirstURLSucceeds", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  2,
			InitialDelay: 1 * time.Millisecond,
			MaxDelay:     10 * time.Millisecond,
			Multiplier:   2.0,
		}
		urls := []string{"http://url1", "http://url2", "http://url3"}

		result, multiResult := RetryMultiURL(context.Background(), config, urls,
			func(ctx context.Context, url string) (string, error) {
				return "from:" + url, nil
			})

		if result != "from:http://url1" {
			t.Errorf("Result = %q, want %q", result, "from:http://url1")
		}
		if !multiResult.Success {
			t.Error("Expected success")
		}
		if multiResult.SuccessfulURL != "http://url1" {
			t.Errorf("SuccessfulURL = %q, want %q", multiResult.SuccessfulURL, "http://url1")
		}
	})

	t.Run("SecondURLSucceeds", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  2,
			InitialDelay: 1 * time.Millisecond,
			MaxDelay:     10 * time.Millisecond,
			Multiplier:   2.0,
		}
		urls := []string{"http://url1", "http://url2", "http://url3"}

		result, multiResult := RetryMultiURL(context.Background(), config, urls,
			func(ctx context.Context, url string) (string, error) {
				if url == "http://url1" {
					return "", errors.New("url1 failed")
				}
				return "from:" + url, nil
			})

		if result != "from:http://url2" {
			t.Errorf("Result = %q, want %q", result, "from:http://url2")
		}
		if !multiResult.Success {
			t.Error("Expected success")
		}
		if multiResult.SuccessfulURL != "http://url2" {
			t.Errorf("SuccessfulURL = %q, want %q", multiResult.SuccessfulURL, "http://url2")
		}
	})

	t.Run("AllURLsFail", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  2,
			InitialDelay: 1 * time.Millisecond,
			MaxDelay:     10 * time.Millisecond,
			Multiplier:   2.0,
		}
		urls := []string{"http://url1", "http://url2"}

		_, multiResult := RetryMultiURL(context.Background(), config, urls,
			func(ctx context.Context, url string) (string, error) {
				return "", errors.New("failed for " + url)
			})

		if multiResult.Success {
			t.Error("Expected failure")
		}
		if len(multiResult.URLErrors) != 2 {
			t.Errorf("URLErrors count = %d, want 2", len(multiResult.URLErrors))
		}
	})
}

func TestRetryMultiURLParallel(t *testing.T) {
	t.Run("FirstSuccessWins", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  2,
			InitialDelay: 1 * time.Millisecond,
			MaxDelay:     10 * time.Millisecond,
			Multiplier:   2.0,
		}
		urls := []string{"http://slow", "http://fast", "http://slower"}

		result, parallelResult := RetryMultiURLParallel(context.Background(), config, urls,
			func(ctx context.Context, url string) (string, error) {
				switch url {
				case "http://slow":
					time.Sleep(100 * time.Millisecond)
				case "http://slower":
					time.Sleep(200 * time.Millisecond)
				case "http://fast":
					// Returns immediately
				}
				return "from:" + url, nil
			})

		if !parallelResult.Success {
			t.Error("Expected success")
		}
		// Fast should win
		if result != "from:http://fast" {
			t.Logf("Result = %q (may vary due to timing)", result)
		}
	})

	t.Run("AllFail", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  1,
			InitialDelay: 1 * time.Millisecond,
			MaxDelay:     10 * time.Millisecond,
			Multiplier:   2.0,
		}
		urls := []string{"http://url1", "http://url2"}

		_, parallelResult := RetryMultiURLParallel(context.Background(), config, urls,
			func(ctx context.Context, url string) (string, error) {
				return "", errors.New("failed")
			})

		if parallelResult.Success {
			t.Error("Expected failure")
		}
	})
}

func TestCircuitBreaker(t *testing.T) {
	t.Run("InitialState", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 2, 100*time.Millisecond)
		if cb.State() != CircuitClosed {
			t.Errorf("Initial state = %v, want Closed", cb.State())
		}
	})

	t.Run("OpensAfterFailures", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 2, 100*time.Millisecond)

		// Record failures
		cb.RecordFailure()
		cb.RecordFailure()
		if cb.State() != CircuitClosed {
			t.Error("Should still be closed after 2 failures")
		}

		cb.RecordFailure()
		if cb.State() != CircuitOpen {
			t.Errorf("State = %v, want Open after 3 failures", cb.State())
		}
	})

	t.Run("BlocksRequestsWhenOpen", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 1, 100*time.Millisecond)
		cb.RecordFailure()

		if cb.Allow() {
			t.Error("Should not allow requests when open")
		}
	})

	t.Run("TransitionsToHalfOpen", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 1, 10*time.Millisecond)
		cb.RecordFailure()

		// Wait for reset timeout
		time.Sleep(20 * time.Millisecond)

		if !cb.Allow() {
			t.Error("Should allow request after reset timeout")
		}
		if cb.State() != CircuitHalfOpen {
			t.Errorf("State = %v, want HalfOpen", cb.State())
		}
	})

	t.Run("ClosesAfterSuccesses", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 2, 10*time.Millisecond)
		cb.RecordFailure()

		// Wait for reset timeout
		time.Sleep(20 * time.Millisecond)
		cb.Allow() // Transition to half-open

		cb.RecordSuccess()
		if cb.State() != CircuitHalfOpen {
			t.Error("Should still be half-open after 1 success")
		}

		cb.RecordSuccess()
		if cb.State() != CircuitClosed {
			t.Errorf("State = %v, want Closed after 2 successes", cb.State())
		}
	})

	t.Run("ReopensOnFailureInHalfOpen", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 2, 10*time.Millisecond)
		cb.RecordFailure()

		// Wait for reset timeout
		time.Sleep(20 * time.Millisecond)
		cb.Allow() // Transition to half-open

		cb.RecordFailure()
		if cb.State() != CircuitOpen {
			t.Errorf("State = %v, want Open after failure in half-open", cb.State())
		}
	})

	t.Run("Reset", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 1, 100*time.Millisecond)
		cb.RecordFailure()

		cb.Reset()
		if cb.State() != CircuitClosed {
			t.Errorf("State = %v, want Closed after reset", cb.State())
		}
		if !cb.Allow() {
			t.Error("Should allow requests after reset")
		}
	})

	t.Run("Execute", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 1, 100*time.Millisecond)

		// Successful execution
		err := cb.Execute(func() error { return nil })
		if err != nil {
			t.Errorf("Execute returned error: %v", err)
		}

		// Failed execution
		err = cb.Execute(func() error { return errors.New("fail") })
		if err == nil {
			t.Error("Execute should return error")
		}

		// Another failed execution should open circuit
		cb.Execute(func() error { return errors.New("fail") })

		// Now circuit should be open
		err = cb.Execute(func() error { return nil })
		if !errors.Is(err, ErrCircuitOpen) {
			t.Errorf("Expected ErrCircuitOpen, got: %v", err)
		}
	})
}

func TestRetryResult(t *testing.T) {
	t.Run("LastError", func(t *testing.T) {
		result := &RetryResult{
			Errors: []error{errors.New("err1"), errors.New("err2")},
		}
		if result.LastError().Error() != "err2" {
			t.Errorf("LastError = %v, want err2", result.LastError())
		}
	})

	t.Run("LastErrorEmpty", func(t *testing.T) {
		result := &RetryResult{}
		if result.LastError() != nil {
			t.Errorf("LastError = %v, want nil", result.LastError())
		}
	})

	t.Run("AllErrors", func(t *testing.T) {
		result := &RetryResult{
			Errors: []error{errors.New("err1"), errors.New("err2")},
		}
		allErr := result.AllErrors()
		if allErr == nil {
			t.Fatal("AllErrors returned nil")
		}
		errStr := allErr.Error()
		if !contains(errStr, "err1") || !contains(errStr, "err2") {
			t.Errorf("AllErrors = %q, should contain err1 and err2", errStr)
		}
	})
}

func TestMultiURLResult(t *testing.T) {
	t.Run("AllErrors", func(t *testing.T) {
		result := &MultiURLResult{
			AttemptedURLs: []string{"http://url1", "http://url2"},
			URLErrors: map[string][]error{
				"http://url1": {errors.New("err1")},
				"http://url2": {errors.New("err2")},
			},
		}
		allErr := result.AllErrors()
		if allErr == nil {
			t.Fatal("AllErrors returned nil")
		}
		errStr := allErr.Error()
		if !contains(errStr, "url1") || !contains(errStr, "url2") {
			t.Errorf("AllErrors = %q, should contain url1 and url2", errStr)
		}
	})

	t.Run("AllErrorsSuccess", func(t *testing.T) {
		result := &MultiURLResult{Success: true}
		if result.AllErrors() != nil {
			t.Error("AllErrors should return nil on success")
		}
	})
}

func TestCircuitStateString(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("CircuitState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
