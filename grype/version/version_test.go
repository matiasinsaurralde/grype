package version

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name           string
		v1             string
		v2             string
		expectedResult int
		expectErr      require.ErrorAssertionFunc
	}{
		{
			name:           "v1 greater than v2",
			v1:             "2.0.0",
			v2:             "1.0.0",
			expectedResult: 1,
		},
		{
			name:           "v1 less than v2",
			v1:             "1.0.0",
			v2:             "2.0.0",
			expectedResult: -1,
		},
		{
			name:           "v1 equal to v2",
			v1:             "1.0.0",
			v2:             "1.0.0",
			expectedResult: 0,
		},
		{
			name:           "compare with nil version",
			v1:             "1.0.0",
			v2:             "",
			expectedResult: -1,
			expectErr:      require.Error,
		},
	}

	// the above test cases are pretty tame value-wise, so we can use (almost) all formats
	var formats []Format
	formats = append(formats, Formats...)

	// leave out some formats...
	slices.DeleteFunc(formats, func(f Format) bool {
		return f == KBFormat
	})

	for _, format := range formats {
		t.Run(format.String(), func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					if tc.expectErr == nil {
						tc.expectErr = require.NoError
					}
					v1 := New(tc.v1, format)
					require.Equal(t, format, v1.Format)

					var v2 *Version
					if tc.v2 != "" {
						v2 = New(tc.v2, format)
						require.Equal(t, format, v2.Format)
					}

					result, err := v1.Compare(v2)
					tc.expectErr(t, err, "unexpected error during comparison")
					if err != nil {
						return // skip further checks if there was an error
					}

					assert.NoError(t, err, "unexpected error during comparison")
					assert.Equal(t, tc.expectedResult, result, "comparison result mismatch")
				})
			}
		})
	}
}

func TestVersion_UpgradeUnknownRightSideComparison(t *testing.T) {
	v1 := New("1.0.0", SemanticFormat)

	// test if we can upgrade an unknown format to a known format when the left hand side is known
	v2 := New("1.0.0", UnknownFormat)

	result, err := v1.Compare(v2)
	assert.NoError(t, err)
	assert.Equal(t, 0, result, "versions should be equal after format conversion")
}

func TestVersionCompareSameFormat(t *testing.T) {
	formats := []struct {
		name   string
		format Format
	}{
		{"Semantic", SemanticFormat},
		{"APK", ApkFormat},
		{"Deb", DebFormat},
		{"Golang", GolangFormat},
		{"Maven", MavenFormat},
		{"RPM", RpmFormat},
		{"Python", PythonFormat},
		{"KB", KBFormat},
		{"Gem", GemFormat},
		{"Portage", PortageFormat},
		{"JVM", JVMFormat},
		{"Unknown", UnknownFormat},
	}

	for _, fmt := range formats {
		t.Run(fmt.name, func(t *testing.T) {
			// just test that we can create and compare versions of this format
			// without errors - not testing the actual comparison logic
			v1 := New("1.0.0", fmt.format)
			v2 := New("1.0.0", fmt.format)

			result, err := v1.Compare(v2)
			assert.NoError(t, err, "comparison error")
			assert.Equal(t, 0, result, "equal versions should return 0")
		})
	}
}

func TestVersion_Is(t *testing.T) {
	tests := []struct {
		name     string
		version  *Version
		operator Operator
		other    *Version
		expected bool
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "equal versions - EQ operator",
			version:  New("1.0.0", SemanticFormat),
			operator: EQ,
			other:    New("1.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "equal versions - empty operator (defaults to EQ)",
			version:  New("1.0.0", SemanticFormat),
			operator: "",
			other:    New("1.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "unequal versions - EQ operator",
			version:  New("1.0.0", SemanticFormat),
			operator: EQ,
			other:    New("2.0.0", SemanticFormat),
			expected: false,
		},
		{
			name:     "greater than - GT operator true",
			version:  New("2.0.0", SemanticFormat),
			operator: GT,
			other:    New("1.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "greater than - GT operator false",
			version:  New("1.0.0", SemanticFormat),
			operator: GT,
			other:    New("2.0.0", SemanticFormat),
			expected: false,
		},
		{
			name:     "greater than or equal - GTE operator true (greater)",
			version:  New("2.0.0", SemanticFormat),
			operator: GTE,
			other:    New("1.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "greater than or equal - GTE operator true (equal)",
			version:  New("1.0.0", SemanticFormat),
			operator: GTE,
			other:    New("1.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "greater than or equal - GTE operator false",
			version:  New("1.0.0", SemanticFormat),
			operator: GTE,
			other:    New("2.0.0", SemanticFormat),
			expected: false,
		},
		{
			name:     "less than - LT operator true",
			version:  New("1.0.0", SemanticFormat),
			operator: LT,
			other:    New("2.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "less than - LT operator false",
			version:  New("2.0.0", SemanticFormat),
			operator: LT,
			other:    New("1.0.0", SemanticFormat),
			expected: false,
		},
		{
			name:     "less than or equal - LTE operator true (less)",
			version:  New("1.0.0", SemanticFormat),
			operator: LTE,
			other:    New("2.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "less than or equal - LTE operator true (equal)",
			version:  New("1.0.0", SemanticFormat),
			operator: LTE,
			other:    New("1.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "less than or equal - LTE operator false",
			version:  New("2.0.0", SemanticFormat),
			operator: LTE,
			other:    New("1.0.0", SemanticFormat),
			expected: false,
		},
		{
			name:     "nil other version should return ErrNoVersionProvided",
			version:  New("1.0.0", SemanticFormat),
			operator: EQ,
			other:    nil,
			wantErr:  require.Error,
		},
		{
			name:     "unknown operator should return error",
			version:  New("1.0.0", SemanticFormat),
			operator: "unknown",
			other:    New("1.0.0", SemanticFormat),
			wantErr:  require.Error,
		},
		{
			name:     "invalid version format should return error",
			version:  New("invalid", SemanticFormat),
			operator: EQ,
			other:    New("1.0.0", SemanticFormat),
			wantErr:  require.Error,
		},
		{
			name:     "different formats - semantic vs apk",
			version:  New("1.0.0", SemanticFormat),
			operator: EQ,
			other:    New("1.0.0", ApkFormat),
			expected: true,
		},
		{
			name:     "complex semantic versions",
			version:  New("1.2.3-alpha.1", SemanticFormat),
			operator: LT,
			other:    New("1.2.3", SemanticFormat),
			expected: true,
		},
		{
			name:     "version with v prefix",
			version:  New("v1.0.0", SemanticFormat),
			operator: EQ,
			other:    New("1.0.0", SemanticFormat),
			expected: true,
		},
		{
			name:     "nil other version is ErrNoVersionProvided",
			version:  New("1.0.0", SemanticFormat),
			operator: EQ,
			other:    nil,
			wantErr: func(t require.TestingT, err error, a ...interface{}) {
				require.ErrorIs(t, err, ErrNoVersionProvided, a...)
			},
		},
		{
			name:     "unknown operator error",
			version:  New("1.0.0", SemanticFormat),
			operator: "!@#",
			other:    New("1.0.0", SemanticFormat),
			wantErr: func(t require.TestingT, err error, a ...interface{}) {
				require.ErrorContains(t, err, "unknown operator !@#", a...)
			},
		},
		{
			name:     "invalid version format error contains format",
			version:  New("not-a-valid-version", SemanticFormat),
			operator: EQ,
			other:    New("1.0.0", SemanticFormat),
			wantErr: func(t require.TestingT, err error, a ...interface{}) {
				require.ErrorContains(t, err, "unable to get comparator for Semantic", a...)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			result, err := tt.version.Is(tt.operator, tt.other)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVersion_Is_AllOperators(t *testing.T) {
	v1 := New("1.0.0", SemanticFormat)
	v2 := New("2.0.0", SemanticFormat)
	v1dup := New("1.0.0", SemanticFormat)

	tests := []struct {
		name     string
		left     *Version
		operator Operator
		right    *Version
		expected bool
	}{
		// v1 (1.0.0) vs v2 (2.0.0)
		{"1.0.0 = 2.0.0", v1, EQ, v2, false},
		{"1.0.0 > 2.0.0", v1, GT, v2, false},
		{"1.0.0 >= 2.0.0", v1, GTE, v2, false},
		{"1.0.0 < 2.0.0", v1, LT, v2, true},
		{"1.0.0 <= 2.0.0", v1, LTE, v2, true},

		// v2 (2.0.0) vs v1 (1.0.0)
		{"2.0.0 = 1.0.0", v2, EQ, v1, false},
		{"2.0.0 > 1.0.0", v2, GT, v1, true},
		{"2.0.0 >= 1.0.0", v2, GTE, v1, true},
		{"2.0.0 < 1.0.0", v2, LT, v1, false},
		{"2.0.0 <= 1.0.0", v2, LTE, v1, false},

		// v1 (1.0.0) vs v1dup (1.0.0)
		{"1.0.0 = 1.0.0", v1, EQ, v1dup, true},
		{"1.0.0 > 1.0.0", v1, GT, v1dup, false},
		{"1.0.0 >= 1.0.0", v1, GTE, v1dup, true},
		{"1.0.0 < 1.0.0", v1, LT, v1dup, false},
		{"1.0.0 <= 1.0.0", v1, LTE, v1dup, true},

		// empty operator should default to EQ
		{"1.0.0 (empty) 1.0.0", v1, "", v1dup, true},
		{"1.0.0 (empty) 2.0.0", v1, "", v2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.left.Is(tt.operator, tt.right)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test_getComparator_doesNotCacheFailures is a regression test for a cache-poisoning
// nil-pointer dereference. Previously, getComparator cached the zero-value comparator
// even when construction failed. The cache-hit path returns a nil error, so a first
// call that failed (e.g. via Validate) would poison the cache, and a subsequent
// Compare/Is would receive a zero-value comparator (semanticVersion{obj: nil}) together
// with a nil error, then dereference the nil inner value and panic. This is reachable
// pre-match (no recover) during distro construction. See
// docs/security/2026-07-version-comparator-cache-panic.md.
func Test_getComparator_doesNotCacheFailures(t *testing.T) {
	// "" is not a valid semantic version, so construction always fails.
	v := New("", SemanticFormat)

	// first interaction fails and must not poison the cache
	err := v.Validate()
	require.Error(t, err)

	// second interaction must still report the error (not a cached, error-less success)
	_, err = v.getComparator(v.Format)
	require.Error(t, err)

	// and comparing must return an error rather than panicking on a nil inner value
	require.NotPanics(t, func() {
		_, cmpErr := v.Compare(New("1.0.0", SemanticFormat))
		require.Error(t, cmpErr)
	})
}

// Test_Compare_afterValidate_unparseable ensures Validate() followed by Compare()/Is()
// on an unparseable version is safe across formats (no nil-pointer panic from a poisoned
// comparator cache).
func Test_Compare_afterValidate_unparseable(t *testing.T) {
	formats := []Format{
		SemanticFormat, ApkFormat, BitnamiFormat, DebFormat, GolangFormat, MavenFormat,
		RpmFormat, PythonFormat, GemFormat, JVMFormat, PacmanFormat,
	}
	for _, f := range formats {
		t.Run(f.String(), func(t *testing.T) {
			v := New("", f)
			_ = v.Validate() // may or may not error depending on format, but must not poison
			require.NotPanics(t, func() {
				_, _ = v.Compare(New("", f))
			})
		})
	}
}
