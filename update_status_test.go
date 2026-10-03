package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNormalizeGitCommit(t *testing.T) {
	valid := "CF49340B9A1234567890ABCDEF1234567890ABCD"
	got := normalizeGitCommit(valid)
	want := "cf49340b9a1234567890abcdef1234567890abcd"
	if got != want {
		t.Fatalf("normalizeGitCommit() = %q, want %q", got, want)
	}
	for _, value := range []string{"", "unknown", "xyz1234", "123 4567", "123456"} {
		if got := normalizeGitCommit(value); got != "" {
			t.Fatalf("normalizeGitCommit(%q) = %q, want empty", value, got)
		}
	}
}

func TestClassifyUpdateStatus(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const latest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	status, upToDate, updateAvailable := classifyUpdateStatus(current, current, false)
	if status != "up_to_date" || !upToDate || updateAvailable {
		t.Fatalf("same clean commit classified as %q, upToDate=%v updateAvailable=%v", status, upToDate, updateAvailable)
	}

	status, upToDate, updateAvailable = classifyUpdateStatus(current, current, true)
	if status != "local_changes" || upToDate || updateAvailable {
		t.Fatalf("modified commit classified as %q, upToDate=%v updateAvailable=%v", status, upToDate, updateAvailable)
	}

	status, upToDate, updateAvailable = classifyUpdateStatus(current, latest, false)
	if status != "update_available" || upToDate || !updateAvailable {
		t.Fatalf("different commit classified as %q, upToDate=%v updateAvailable=%v", status, upToDate, updateAvailable)
	}
}

func TestRepoWebURLRemovesCredentialsAndGitSuffix(t *testing.T) {
	got := repoWebURL("https://user:secret@git.example.test/owner/repo.git")
	want := "https://git.example.test/owner/repo"
	if got != want {
		t.Fatalf("repoWebURL() = %q, want %q", got, want)
	}
}

func TestQueryRemoteCommit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script git stub is Unix-specific")
	}
	const want = "cf49340b9a1234567890abcdef1234567890abcd"
	dir := t.TempDir()
	gitPath := filepath.Join(dir, "git")
	script := "#!/bin/sh\nprintf '%s\\trefs/heads/main\\n' '" + want + "'\n"
	if err := os.WriteFile(gitPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got, err := queryRemoteCommit(context.Background(), "https://git.example.test/owner/repo.git", "main")
	if err != nil {
		t.Fatalf("queryRemoteCommit() error = %v", err)
	}
	if got != want {
		t.Fatalf("queryRemoteCommit() = %q, want %q", got, want)
	}
}
