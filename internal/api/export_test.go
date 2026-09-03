package api

import "time"

// SetRecoveryClientForTest replaces the KyRecovery pairing client. Test-only: this file is not
// part of the package build.
func SetRecoveryClientForTest(s *Server, p recoveryPairer) { s.recovery = p }

// AttemptsCapForTest is the limiter's hard bound on distinct keys.
const AttemptsCapForTest = attemptsCap

// AttemptKeysForTest returns the limiter's live keys. Test-only: this file is not part of the
// package build.
func AttemptKeysForTest(s *Server) []string {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	keys := make([]string, 0, len(s.attempts))
	for k := range s.attempts {
		keys = append(keys, k)
	}
	return keys
}

// AllowAttemptForTest drives the limiter directly so a test can fill it without paying for
// 10 000 HTTP requests. Test-only.
func AllowAttemptForTest(s *Server, key string, limit int, window time.Duration) bool {
	return s.allowAttempt(key, limit, window)
}
