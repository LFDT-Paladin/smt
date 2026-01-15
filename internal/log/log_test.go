// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLogger(t *testing.T) {
	// Test that logger() returns a non-nil entry
	entry := logger()
	assert.NotNil(t, entry)
	assert.Equal(t, logrus.StandardLogger(), entry.Logger)
}

func TestL(t *testing.T) {
	// Test that L() function variable works
	entry := L()
	assert.NotNil(t, entry)
	assert.Equal(t, logrus.StandardLogger(), entry.Logger)
}

func TestWithLogField(t *testing.T) {
	t.Run("normal value", func(t *testing.T) {
		key := "test_key"
		value := "test_value"
		entry := WithLogField(key, value)

		assert.NotNil(t, entry)
		// Verify the field is set by checking the data
		assert.Equal(t, value, entry.Data[key])
	})

	t.Run("short value", func(t *testing.T) {
		key := "short_key"
		value := "short"
		entry := WithLogField(key, value)

		assert.NotNil(t, entry)
		assert.Equal(t, value, entry.Data[key])
	})

	t.Run("exactly 61 characters", func(t *testing.T) {
		key := "exact_key"
		value := "1234567890123456789012345678901234567890123456789012345678901" // 61 chars
		entry := WithLogField(key, value)

		assert.NotNil(t, entry)
		assert.Equal(t, value, entry.Data[key], "value should not be truncated at exactly 61 chars")
	})

	t.Run("value longer than 61 characters gets truncated", func(t *testing.T) {
		key := "long_key"
		value := "1234567890123456789012345678901234567890123456789012345678901234567890" // 70 chars
		expected := "1234567890123456789012345678901234567890123456789012345678901..." // 61 + 3 = 64
		entry := WithLogField(key, value)

		assert.NotNil(t, entry)
		assert.Equal(t, expected, entry.Data[key], "value should be truncated to 61 chars + ...")
	})

	t.Run("very long value", func(t *testing.T) {
		key := "very_long_key"
		// Create a 200 character string
		longValue := ""
		for i := 0; i < 200; i++ {
			longValue += "x"
		}
		entry := WithLogField(key, longValue)

		assert.NotNil(t, entry)
		truncatedValue := entry.Data[key].(string)
		assert.Len(t, truncatedValue, 64, "truncated value should be 61 chars + '...' = 64 chars")
		assert.Equal(t, longValue[:61], truncatedValue[:61], "first 61 characters should match")
		assert.Equal(t, "...", truncatedValue[61:], "should end with '...'")
	})

	t.Run("empty value", func(t *testing.T) {
		key := "empty_key"
		value := ""
		entry := WithLogField(key, value)

		assert.NotNil(t, entry)
		assert.Equal(t, value, entry.Data[key])
	})

	t.Run("multiple fields", func(t *testing.T) {
		entry1 := WithLogField("key1", "value1")
		entry2 := entry1.WithField("key2", "value2")

		assert.NotNil(t, entry2)
		assert.Equal(t, "value1", entry2.Data["key1"])
		assert.Equal(t, "value2", entry2.Data["key2"])
	})
}

func TestInitConfig(t *testing.T) {
	// Save original logrus configuration
	originalLevel := logrus.GetLevel()
	originalOutput := logrus.StandardLogger().Out
	originalFormatter := logrus.StandardLogger().Formatter
	originalReportCaller := logrus.StandardLogger().ReportCaller

	// Restore original configuration after test
	defer func() {
		logrus.SetLevel(originalLevel)
		logrus.SetOutput(originalOutput)
		logrus.SetFormatter(originalFormatter)
		logrus.StandardLogger().SetReportCaller(originalReportCaller)
	}()

	// Test InitConfig
	InitConfig()

	// Verify log level is set to InfoLevel
	assert.Equal(t, logrus.InfoLevel, logrus.GetLevel())

	// Verify output is set to stdout
	assert.Equal(t, os.Stdout, logrus.StandardLogger().Out)

	// Verify formatter is set (should be utcFormat wrapper)
	formatter := logrus.StandardLogger().Formatter
	assert.NotNil(t, formatter)
	// The formatter should be a utcFormat wrapping a prefixed.TextFormatter
	_, ok := formatter.(*utcFormat)
	assert.True(t, ok, "formatter should be utcFormat")

	// Verify ReportCaller is enabled
	assert.True(t, logrus.StandardLogger().ReportCaller)
}

func TestInitConfig_CanBeCalledMultipleTimes(t *testing.T) {
	// Save original logrus configuration
	originalLevel := logrus.GetLevel()
	originalOutput := logrus.StandardLogger().Out
	originalFormatter := logrus.StandardLogger().Formatter
	originalReportCaller := logrus.StandardLogger().ReportCaller

	// Restore original configuration after test
	defer func() {
		logrus.SetLevel(originalLevel)
		logrus.SetOutput(originalOutput)
		logrus.SetFormatter(originalFormatter)
		logrus.StandardLogger().SetReportCaller(originalReportCaller)
	}()

	// Call InitConfig multiple times
	InitConfig()
	firstFormatter := logrus.StandardLogger().Formatter

	InitConfig()
	secondFormatter := logrus.StandardLogger().Formatter

	// Both calls should work without panicking
	assert.NotNil(t, firstFormatter)
	assert.NotNil(t, secondFormatter)
}

func TestUtcFormat(t *testing.T) {
	// Create a mock formatter
	mockFormatter := &mockFormatter{}
	utcFormatter := &utcFormat{f: mockFormatter}

	// Create a log entry with a non-UTC time
	entry := &logrus.Entry{
		Time:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.FixedZone("EST", -5*3600)),
		Level:   logrus.InfoLevel,
		Message: "test message",
	}

	// Format the entry
	_, err := utcFormatter.Format(entry)

	// Verify no error
	assert.NoError(t, err)

	// Verify the time was converted to UTC
	assert.Equal(t, time.UTC, entry.Time.Location())
	// The time should be 5 hours ahead (EST to UTC)
	expectedTime := time.Date(2024, 1, 15, 15, 30, 0, 0, time.UTC)
	assert.Equal(t, expectedTime, entry.Time)
}

func TestUtcFormat_AlreadyUTC(t *testing.T) {
	// Create a mock formatter
	mockFormatter := &mockFormatter{}
	utcFormatter := &utcFormat{f: mockFormatter}

	// Create a log entry with UTC time
	originalTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	entry := &logrus.Entry{
		Time:    originalTime,
		Level:   logrus.InfoLevel,
		Message: "test message",
	}

	// Format the entry
	_, err := utcFormatter.Format(entry)

	// Verify no error
	assert.NoError(t, err)

	// Verify the time is still UTC
	assert.Equal(t, time.UTC, entry.Time.Location())
	assert.Equal(t, originalTime, entry.Time)
}

func TestUtcFormat_WithRealFormatter(t *testing.T) {
	// Use a real logrus formatter
	realFormatter := &logrus.TextFormatter{}
	utcFormatter := &utcFormat{f: realFormatter}

	// Create a log entry
	entry := &logrus.Entry{
		Time:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.FixedZone("EST", -5*3600)),
		Level:   logrus.InfoLevel,
		Message: "test message",
		Logger:  logrus.StandardLogger(),
	}

	// Format the entry
	formatted, err := utcFormatter.Format(entry)

	// Verify no error and output is not empty
	assert.NoError(t, err)
	assert.NotEmpty(t, formatted)

	// Verify the time was converted to UTC
	assert.Equal(t, time.UTC, entry.Time.Location())
}

func TestLoggerIntegration(t *testing.T) {
	// Test that L() and logger() return the same logger
	entry1 := L()
	entry2 := logger()

	assert.Equal(t, entry1.Logger, entry2.Logger)
}

func TestWithLogField_Integration(t *testing.T) {
	// Test that WithLogField can be used with log methods
	var buf bytes.Buffer
	logrus.SetOutput(&buf)
	defer logrus.SetOutput(os.Stdout)

	entry := WithLogField("test_key", "test_value")
	entry.Info("test message")

	output := buf.String()
	assert.Contains(t, output, "test_key")
	assert.Contains(t, output, "test_value")
	assert.Contains(t, output, "test message")
}

// mockFormatter is a simple formatter for testing
type mockFormatter struct {
	formatCalled bool
}

func (m *mockFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	m.formatCalled = true
	return []byte("mock formatted"), nil
}

