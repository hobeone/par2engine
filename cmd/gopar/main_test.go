package main

import (
	"log/slog"
	"os"
	"testing"

	"github.com/hobeone/par2engine/par2"
)

func TestHandleVerifyCommand(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	tests := []struct {
		name     string
		counts   par2.ShardCounts
		expected int
	}{
		{
			name: "no repair needed",
			counts: par2.ShardCounts{
				UsableDataShardCount:   10,
				UnusableDataShardCount: 0,
				UsableParityShardCount: 5,
				RenamesNeeded:          0,
			},
			expected: ExitSuccess,
		},
		{
			name: "repair possible",
			counts: par2.ShardCounts{
				UsableDataShardCount:   9,
				UnusableDataShardCount: 1,
				UsableParityShardCount: 5,
				RenamesNeeded:          0,
			},
			expected: ExitRepairPossible,
		},
		{
			name: "repair not possible",
			counts: par2.ShardCounts{
				UsableDataShardCount:   8,
				UnusableDataShardCount: 3,
				UsableParityShardCount: 2,
				RenamesNeeded:          0,
			},
			expected: ExitRepairNotPossible,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handleVerifyCommand(logger, tt.counts)
			if got != tt.expected {
				t.Errorf("handleVerifyCommand() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSetupProfiling(t *testing.T) {
	cleanup, err := setupProfiling("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected cleanup function, got nil")
	}
	cleanup()
}
