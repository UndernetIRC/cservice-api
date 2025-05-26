package helper

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSecureToken(t *testing.T) {
	length := 16
	token1 := GenerateSecureToken(length)
	token2 := GenerateSecureToken(length)

	assert.Equal(t, length, len(token1), "Token should have the specified length")
	assert.NotEmpty(t, token1, "Token should not be empty")

	assert.Equal(t, length, len(token2), "Second token should also have the specified length")
	assert.NotEmpty(t, token2, "Second token should not be empty")

	assert.NotEqual(t, token1, token2, "Consecutively generated tokens should be different")
}

func TestCryptoRandomInt(t *testing.T) {
	limit := int64(100)
	results := make(map[int64]struct{})
	iterations := 200 // Generate multiple times to check distribution roughly

	for i := 0; i < iterations; i++ {
		val, err := CryptoRandomInt(limit)
		assert.NoError(t, err, "CryptoRandomInt should not return an error")
		assert.GreaterOrEqual(t, val, int64(0), "Value should be non-negative")
		assert.Less(t, val, limit, "Value should be less than the limit")
		results[val] = struct{}{}
	}

	// Check if we got a reasonable distribution (not all the same value)
	// This is not a perfect test for randomness but catches basic issues.
	assert.Greater(t, len(results), 1, "Should generate more than one distinct value over several iterations")

	// Test edge case: limit 1 should always return 0
	valZero, errZero := CryptoRandomInt(1)
	assert.NoError(t, errZero, "CryptoRandomInt with limit 1 should not error")
	assert.Equal(t, int64(0), valZero, "CryptoRandomInt with limit 1 should return 0")

	// Test invalid limit (though the underlying crypto/rand handles negative, let's test 0)
	_, errNegative := CryptoRandomInt(0)
	assert.Error(t, errNegative, "CryptoRandomInt with limit 0 should return an error")
}

func TestCryptoRandomString(t *testing.T) {
	length := int64(32)
	str1, err1 := CryptoRandomString(length)
	str2, err2 := CryptoRandomString(length)

	assert.NoError(t, err1, "CryptoRandomString should not return an error")
	assert.Equal(t, int(length), len(str1), "String should have the specified length")
	assert.NotEmpty(t, str1, "String should not be empty")

	// Verify characters are alphanumeric
	alphanumericRegex := regexp.MustCompile("^[a-zA-Z0-9]+$")
	assert.True(t, alphanumericRegex.MatchString(str1), "String should only contain alphanumeric characters")

	assert.NoError(t, err2, "Second call to CryptoRandomString should not return an error")
	assert.Equal(t, int(length), len(str2), "Second string should also have the specified length")
	assert.NotEmpty(t, str2, "Second string should not be empty")
	assert.True(t, alphanumericRegex.MatchString(str2), "Second string should only contain alphanumeric characters")

	assert.NotEqual(t, str1, str2, "Consecutively generated strings should be different")

	// Test zero length
	strZero, errZero := CryptoRandomString(0)
	assert.NoError(t, errZero, "CryptoRandomString with length 0 should not error")
	assert.Empty(t, strZero, "CryptoRandomString with length 0 should return an empty string")
}
