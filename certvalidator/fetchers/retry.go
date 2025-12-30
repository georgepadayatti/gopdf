package fetchers

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// RetryConfig configures retry behavior for external requests.
type RetryConfig struct {
	// MaxAttempts is the maximum number of attempts (including the first try).
	// Default: 3
	MaxAttempts int

	// InitialDelay is the delay before the first retry.
	// Default: 1 second
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries.
	// Default: 30 seconds
	MaxDelay time.Duration

	// Multiplier is the factor by which delay increases after each retry.
	// Default: 2.0 (exponential backoff)
	Multiplier float64

	// Jitter adds randomness to delays to prevent thundering herd.
	// Value between 0 and 1, where 0.1 means ±10% jitter.
	// Default: 0.1
	Jitter float64

	// RetryableErrors is a list of error types that should trigger a retry.
	// If nil, all errors are retryable except context cancellation.
	RetryableErrors []error

	// OnRetry is called before each retry attempt.
	// Can be used for logging or metrics.
	OnRetry func(attempt int, err error, delay time.Duration)
}

// DefaultRetryConfig returns a default retry configuration with exponential backoff.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.1,
	}
}

// AggressiveRetryConfig returns a configuration for more aggressive retrying.
// Useful for critical operations where availability is important.
func AggressiveRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:  5,
		InitialDelay: 500 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   1.5,
		Jitter:       0.2,
	}
}

// ConservativeRetryConfig returns a configuration for conservative retrying.
// Useful when you want to minimize load on external services.
func ConservativeRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:  2,
		InitialDelay: 2 * time.Second,
		MaxDelay:     60 * time.Second,
		Multiplier:   3.0,
		Jitter:       0.1,
	}
}

// calculateDelay calculates the delay for a given attempt number.
func (c *RetryConfig) calculateDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	// Calculate base delay with exponential backoff
	delay := float64(c.InitialDelay) * math.Pow(c.Multiplier, float64(attempt-1))

	// Apply max delay cap
	if delay > float64(c.MaxDelay) {
		delay = float64(c.MaxDelay)
	}

	// Apply jitter
	if c.Jitter > 0 {
		jitterRange := delay * c.Jitter
		delay = delay - jitterRange + (rand.Float64() * 2 * jitterRange)
	}

	return time.Duration(delay)
}

// isRetryable determines if an error should trigger a retry.
func (c *RetryConfig) isRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Never retry context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// If no specific retryable errors defined, retry all
	if len(c.RetryableErrors) == 0 {
		return true
	}

	// Check if error matches any retryable error
	for _, retryableErr := range c.RetryableErrors {
		if errors.Is(err, retryableErr) {
			return true
		}
	}

	return false
}

// RetryResult contains the result of a retry operation.
type RetryResult struct {
	// Attempts is the number of attempts made.
	Attempts int

	// TotalDuration is the total time spent including all retries.
	TotalDuration time.Duration

	// Errors contains all errors encountered during retries.
	Errors []error

	// Success indicates if the operation ultimately succeeded.
	Success bool
}

// LastError returns the last error encountered, or nil if successful.
func (r *RetryResult) LastError() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return r.Errors[len(r.Errors)-1]
}

// AllErrors returns a combined error with all attempt errors.
func (r *RetryResult) AllErrors() error {
	if len(r.Errors) == 0 {
		return nil
	}

	msgs := make([]string, len(r.Errors))
	for i, err := range r.Errors {
		msgs[i] = fmt.Sprintf("attempt %d: %v", i+1, err)
	}
	return fmt.Errorf("all attempts failed: %s", strings.Join(msgs, "; "))
}

// Retry executes a function with retry logic.
func Retry[T any](ctx context.Context, config *RetryConfig, fn func(ctx context.Context) (T, error)) (T, *RetryResult) {
	if config == nil {
		config = DefaultRetryConfig()
	}

	result := &RetryResult{}
	start := time.Now()

	var zero T
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		result.Attempts = attempt

		// Execute the function
		value, err := fn(ctx)
		if err == nil {
			result.Success = true
			result.TotalDuration = time.Since(start)
			return value, result
		}

		result.Errors = append(result.Errors, err)

		// Check if we should retry
		if attempt >= config.MaxAttempts || !config.isRetryable(err) {
			break
		}

		// Calculate delay
		delay := config.calculateDelay(attempt)

		// Call OnRetry callback if set
		if config.OnRetry != nil {
			config.OnRetry(attempt, err, delay)
		}

		// Wait before retrying
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, ctx.Err())
			result.TotalDuration = time.Since(start)
			return zero, result
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	result.TotalDuration = time.Since(start)
	return zero, result
}

// MultiURLResult contains the result of attempting multiple URLs.
type MultiURLResult struct {
	// SuccessfulURL is the URL that succeeded, if any.
	SuccessfulURL string

	// AttemptedURLs is the list of URLs that were attempted.
	AttemptedURLs []string

	// URLErrors maps each URL to the errors encountered.
	URLErrors map[string][]error

	// TotalAttempts is the total number of attempts across all URLs.
	TotalAttempts int

	// TotalDuration is the total time spent across all URLs.
	TotalDuration time.Duration

	// Success indicates if any URL succeeded.
	Success bool
}

// AllErrors returns a combined error with all URL errors.
func (r *MultiURLResult) AllErrors() error {
	if r.Success {
		return nil
	}

	var msgs []string
	for _, url := range r.AttemptedURLs {
		if errs, ok := r.URLErrors[url]; ok && len(errs) > 0 {
			errStrs := make([]string, len(errs))
			for i, err := range errs {
				errStrs[i] = err.Error()
			}
			msgs = append(msgs, fmt.Sprintf("%s: [%s]", url, strings.Join(errStrs, ", ")))
		}
	}

	if len(msgs) == 0 {
		return fmt.Errorf("all URLs failed")
	}
	return fmt.Errorf("all URLs failed: %s", strings.Join(msgs, "; "))
}

// RetryMultiURL attempts to execute a function across multiple URLs with retry logic.
// It tries each URL in order, with retries per URL, and returns on first success.
func RetryMultiURL[T any](
	ctx context.Context,
	config *RetryConfig,
	urls []string,
	fn func(ctx context.Context, url string) (T, error),
) (T, *MultiURLResult) {
	if config == nil {
		config = DefaultRetryConfig()
	}

	result := &MultiURLResult{
		AttemptedURLs: make([]string, 0, len(urls)),
		URLErrors:     make(map[string][]error),
	}
	start := time.Now()

	var zero T
	for _, url := range urls {
		result.AttemptedURLs = append(result.AttemptedURLs, url)

		value, retryResult := Retry(ctx, config, func(ctx context.Context) (T, error) {
			return fn(ctx, url)
		})

		result.TotalAttempts += retryResult.Attempts
		result.URLErrors[url] = retryResult.Errors

		if retryResult.Success {
			result.SuccessfulURL = url
			result.Success = true
			result.TotalDuration = time.Since(start)
			return value, result
		}

		// Check if context is done
		if ctx.Err() != nil {
			break
		}
	}

	result.TotalDuration = time.Since(start)
	return zero, result
}

// ParallelMultiURLResult contains the result of parallel URL attempts.
type ParallelMultiURLResult struct {
	MultiURLResult

	// FirstSuccessURL is the first URL that succeeded (may differ from SuccessfulURL).
	FirstSuccessURL string
}

// RetryMultiURLParallel attempts to execute a function across multiple URLs in parallel.
// Returns as soon as any URL succeeds.
func RetryMultiURLParallel[T any](
	ctx context.Context,
	config *RetryConfig,
	urls []string,
	fn func(ctx context.Context, url string) (T, error),
) (T, *ParallelMultiURLResult) {
	if config == nil {
		config = DefaultRetryConfig()
	}

	result := &ParallelMultiURLResult{
		MultiURLResult: MultiURLResult{
			AttemptedURLs: urls,
			URLErrors:     make(map[string][]error),
		},
	}
	start := time.Now()

	// Create a cancellable context for stopping other goroutines on success
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type urlResult struct {
		url    string
		value  T
		result *RetryResult
	}

	resultChan := make(chan urlResult, len(urls))
	var wg sync.WaitGroup

	// Start goroutines for each URL
	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()

			value, retryResult := Retry(ctx, config, func(ctx context.Context) (T, error) {
				return fn(ctx, u)
			})

			resultChan <- urlResult{
				url:    u,
				value:  value,
				result: retryResult,
			}
		}(url)
	}

	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var zero T
	var firstSuccess *urlResult
	urlErrorsMu := sync.Mutex{}

	for r := range resultChan {
		urlErrorsMu.Lock()
		result.URLErrors[r.url] = r.result.Errors
		result.TotalAttempts += r.result.Attempts
		urlErrorsMu.Unlock()

		if r.result.Success && firstSuccess == nil {
			firstSuccess = &r
			cancel() // Cancel other goroutines
		}
	}

	result.TotalDuration = time.Since(start)

	if firstSuccess != nil {
		result.Success = true
		result.SuccessfulURL = firstSuccess.url
		result.FirstSuccessURL = firstSuccess.url
		return firstSuccess.value, result
	}

	return zero, result
}

// CircuitBreaker implements a simple circuit breaker pattern for external services.
type CircuitBreaker struct {
	mu sync.RWMutex

	// Configuration
	failureThreshold int           // Number of failures before opening
	successThreshold int           // Number of successes to close after half-open
	resetTimeout     time.Duration // Time before trying again after open

	// State
	state         CircuitState
	failures      int
	successes     int
	lastFailure   time.Time
	lastStateChange time.Time
}

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// String returns a string representation of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(failureThreshold, successThreshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		resetTimeout:     resetTimeout,
		state:            CircuitClosed,
		lastStateChange:  time.Now(),
	}
}

// DefaultCircuitBreaker returns a circuit breaker with default settings.
func DefaultCircuitBreaker() *CircuitBreaker {
	return NewCircuitBreaker(5, 2, 30*time.Second)
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Allow checks if a request should be allowed through.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if reset timeout has passed
		if time.Since(cb.lastFailure) >= cb.resetTimeout {
			cb.state = CircuitHalfOpen
			cb.lastStateChange = time.Now()
			cb.successes = 0
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitHalfOpen:
		cb.successes++
		if cb.successes >= cb.successThreshold {
			cb.state = CircuitClosed
			cb.lastStateChange = time.Now()
			cb.failures = 0
		}
	case CircuitClosed:
		cb.failures = 0 // Reset failures on success
	}
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailure = time.Now()

	switch cb.state {
	case CircuitClosed:
		cb.failures++
		if cb.failures >= cb.failureThreshold {
			cb.state = CircuitOpen
			cb.lastStateChange = time.Now()
		}
	case CircuitHalfOpen:
		cb.state = CircuitOpen
		cb.lastStateChange = time.Now()
	}
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = CircuitClosed
	cb.failures = 0
	cb.successes = 0
	cb.lastStateChange = time.Now()
}

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// Execute executes a function with circuit breaker protection.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if !cb.Allow() {
		return ErrCircuitOpen
	}

	err := fn()
	if err != nil {
		cb.RecordFailure()
		return err
	}

	cb.RecordSuccess()
	return nil
}
