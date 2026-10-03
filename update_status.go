package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

const (
	defaultUpdateRepoURL = "https://github.com/dakarpy/ConectaSSH-PRO.git"
	defaultUpdateBranch  = "main"
	updateStatusCacheTTL = 5 * time.Minute
	updateCheckTimeout   = 12 * time.Second
)

// These values are injected by install.sh/update.sh with -ldflags. The
// runtime/debug fallback keeps the endpoint useful for normal git builds.
var (
	buildCommit  = ""
	buildBranch  = ""
	buildTime    = ""
	buildRepoURL = ""
)

type updateStatusResponse struct {
	Status             string `json:"status"`
	UpToDate           bool   `json:"up_to_date"`
	UpdateAvailable    bool   `json:"update_available"`
	LocalModified      bool   `json:"local_modified"`
	CurrentCommit      string `json:"current_commit,omitempty"`
	CurrentCommitShort string `json:"current_commit_short,omitempty"`
	LatestCommit       string `json:"latest_commit,omitempty"`
	LatestCommitShort  string `json:"latest_commit_short,omitempty"`
	Branch             string `json:"branch"`
	BuildTime          string `json:"build_time,omitempty"`
	RepoURL            string `json:"repo_url"`
	RepoWebURL         string `json:"repo_web_url"`
	CheckedAt          string `json:"checked_at"`
	Cached             bool   `json:"cached"`
	Error              string `json:"error,omitempty"`
}

var updateStatusCache struct {
	sync.Mutex
	checkedAt time.Time
	response  updateStatusResponse
}

func handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}

	force := r.URL.Query().Get("refresh") == "1"
	resp := getUpdateStatus(r.Context(), force)
	_ = json.NewEncoder(w).Encode(resp)
}

func getUpdateStatus(parent context.Context, force bool) updateStatusResponse {
	updateStatusCache.Lock()
	defer updateStatusCache.Unlock()

	if !force && !updateStatusCache.checkedAt.IsZero() && time.Since(updateStatusCache.checkedAt) < updateStatusCacheTTL {
		resp := updateStatusCache.response
		resp.Cached = true
		return resp
	}

	resp := checkRemoteUpdate(parent)
	updateStatusCache.checkedAt = time.Now()
	updateStatusCache.response = resp
	return resp
}

func checkRemoteUpdate(parent context.Context) updateStatusResponse {
	repoURL := firstNonEmptyTrimmed(
		strings.TrimSpace(os.Getenv("DRAGON_UPDATE_REPO_URL")),
		readSingleLineFile("/opt/sshpanel/.installed_repo_url"),
		strings.TrimSpace(buildRepoURL),
		defaultUpdateRepoURL,
	)
	branch := firstNonEmptyTrimmed(
		strings.TrimSpace(os.Getenv("DRAGON_UPDATE_BRANCH")),
		strings.TrimSpace(buildBranch),
		readSingleLineFile("/opt/sshpanel/.installed_branch"),
		defaultUpdateBranch,
	)
	currentCommit, localModified, resolvedBuildTime := resolveCurrentBuildInfo()
	if resolvedBuildTime == "" {
		resolvedBuildTime = readSingleLineFile("/opt/sshpanel/.installed_build_time")
	}
	if currentCommit == "" {
		currentCommit = normalizeGitCommit(readSingleLineFile("/opt/sshpanel/.installed_commit"))
	}

	now := time.Now().UTC().Format(time.RFC3339)
	resp := updateStatusResponse{
		Status:             "unknown",
		CurrentCommit:      currentCommit,
		CurrentCommitShort: shortCommit(currentCommit),
		Branch:             branch,
		BuildTime:          resolvedBuildTime,
		RepoURL:            safeRepoURL(repoURL),
		RepoWebURL:         repoWebURL(repoURL),
		CheckedAt:          now,
		LocalModified:      localModified,
	}

	ctx, cancel := context.WithTimeout(parent, updateCheckTimeout)
	defer cancel()

	latestCommit, err := queryRemoteCommit(ctx, repoURL, branch)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			resp.Error = "remote update check timed out"
		} else {
			resp.Error = "could not read the remote Git branch"
		}
		return resp
	}

	resp.LatestCommit = latestCommit
	resp.LatestCommitShort = shortCommit(latestCommit)

	if currentCommit == "" {
		resp.Error = "current build commit is unavailable"
		return resp
	}

	resp.Status, resp.UpToDate, resp.UpdateAvailable = classifyUpdateStatus(currentCommit, latestCommit, localModified)
	return resp
}

func classifyUpdateStatus(currentCommit, latestCommit string, localModified bool) (status string, upToDate bool, updateAvailable bool) {
	if currentCommit == "" || latestCommit == "" {
		return "unknown", false, false
	}
	if strings.EqualFold(currentCommit, latestCommit) {
		if localModified {
			return "local_changes", false, false
		}
		return "up_to_date", true, false
	}
	return "update_available", false, true
}

func queryRemoteCommit(ctx context.Context, repoURL, branch string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--exit-code", "--heads", repoURL, "refs/heads/"+branch)
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
	)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", errors.New("invalid git ls-remote response")
	}
	commit := normalizeGitCommit(fields[0])
	if commit == "" {
		return "", errors.New("invalid remote commit")
	}
	return commit, nil
}

func resolveCurrentBuildInfo() (commit string, modified bool, builtAt string) {
	commit = normalizeGitCommit(buildCommit)
	builtAt = strings.TrimSpace(buildTime)

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return commit, false, builtAt
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if commit == "" {
				commit = normalizeGitCommit(setting.Value)
			}
		case "vcs.modified":
			modified = strings.EqualFold(setting.Value, "true")
		case "vcs.time":
			if builtAt == "" {
				builtAt = strings.TrimSpace(setting.Value)
			}
		}
	}
	return commit, modified, builtAt
}

func normalizeGitCommit(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "unknown") || len(value) < 7 || len(value) > 64 {
		return ""
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return ""
		}
	}
	return strings.ToLower(value)
}

func shortCommit(commit string) string {
	if len(commit) <= 12 {
		return commit
	}
	return commit[:12]
}

func readSingleLineFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	return line
}

func firstNonEmptyTrimmed(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func safeRepoURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	u.User = nil
	return u.String()
}

func repoWebURL(raw string) string {
	value := safeRepoURL(raw)
	return strings.TrimSuffix(value, ".git")
}
