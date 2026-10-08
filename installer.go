package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed install.sh
var embeddedInstaller []byte

const installerRepo = "https://github.com/dakarpy/ConectaSSH-PRO.git"

type installerPort struct {
	protocol string
	port     int
	free     bool
	owner    string
}
type installerReport struct {
	os, arch      string
	cpus          int
	ramMB, diskGB uint64
	systemd       bool
	ports         []installerPort
	existing      []string
}

func runInstallerMode() int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: ejecutá el instalador inteligente como root.")
		return 1
	}
	r := inspectInstallerHost()
	printInstallerReport(r)
	fmt.Println("\n[INTELIGENTE] Puerto libre → Conecta puede usarlo; puerto ocupado → queda intacto.")
	fmt.Println("[INTELIGENTE] No se detienen, matan, deshabilitan ni reconfiguran servicios ajenos.")
	if err := executeEmbeddedInstaller(); err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR: instalación: %v\n", err)
		return 1
	}
	return 0
}

func inspectInstallerHost() installerReport {
	r := installerReport{os: readOSName(), arch: runtime.GOARCH, cpus: runtime.NumCPU(), ramMB: readRAMMB(), diskGB: readFreeDiskGB("/")}
	r.systemd = commandExists("systemctl") && fileExists("/run/systemd/system")
	for _, p := range []struct {
		proto string
		port  int
	}{{"TCP", 80}, {"TCP", 443}, {"TCP", 8080}, {"TCP", 8880}, {"TCP", 9090}, {"TCP", 10086}, {"UDP", 53}, {"UDP", 7300}} {
		r.ports = append(r.ports, inspectPort(p.proto, p.port))
	}
	for _, p := range []string{"/opt/sshpanel", "/etc/systemd/system/sshpanel.service", "/etc/systemd/system/sshpanel-dnstt-redirect.service", "/usr/local/bin/conecta"} {
		if fileExists(p) {
			r.existing = append(r.existing, p)
		}
	}
	return r
}

func printInstallerReport(r installerReport) {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          CONECTASSH-PRO · INSTALADOR INTELIGENTE           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  SO           : %s\n  Arquitectura : %s\n  CPU          : %d\n  RAM          : %d MB\n  Disco libre  : %d GB\n  systemd      : %v\n", r.os, r.arch, r.cpus, r.ramMB, r.diskGB, r.systemd)
	fmt.Println("  Puertos:")
	for _, p := range r.ports {
		if p.free {
			fmt.Printf("    ✓ %s/%d LIBRE → disponible\n", p.protocol, p.port)
		} else {
			fmt.Printf("    ! %s/%d OCUPADO → intacto (%s)\n", p.protocol, p.port, p.owner)
		}
	}
	if len(r.existing) > 0 {
		fmt.Println("  Conecta existente:")
		for _, p := range r.existing {
			fmt.Println("    •", p)
		}
	}
}

func inspectPort(proto string, port int) installerPort {
	p := installerPort{protocol: proto, port: port, free: true}
	network := "tcp"
	if proto == "UDP" {
		network = "udp"
	}
	ln, err := net.Listen(network, net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err == nil {
		_ = ln.Close()
		return p
	}
	p.free = false
	p.owner = findPortOwner(proto, port)
	return p
}
func findPortOwner(proto string, port int) string {
	if !commandExists("ss") {
		return ""
	}
	flag := "-ltnp"
	if proto == "UDP" {
		flag = "-lunp"
	}
	out, err := exec.Command("ss", flag, fmt.Sprintf("sport = :%d", port)).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "users:(("); i >= 0 {
			return line[i:]
		}
	}
	return ""
}

func executeEmbeddedInstaller() error {
	tmp, err := os.MkdirTemp("", "conecta-installer-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	repo := filepath.Join(tmp, "repo")
	if err := downloadRepository(repo); err != nil {
		return err
	}
	script := filepath.Join(repo, "install.sh")
	if err := os.WriteFile(script, embeddedInstaller, 0700); err != nil {
		return err
	}
	cmd := exec.Command("/bin/bash", script)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CONTECTA_INTELLIGENT_INSTALL=1", "CONTECTA_PORT_POLICY=never_takeover")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func downloadRepository(dst string) error {
	parent := filepath.Dir(dst)
	archive := filepath.Join(parent, "repo.tar.gz")
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "curl", "-fsSL", installerRepo+"/archive/refs/heads/main.tar.gz", "-o", archive).CombinedOutput(); err != nil {
		return fmt.Errorf("descarga GitHub: %v: %s", err, strings.TrimSpace(string(out)))
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		rel := filepath.Clean(h.Name)
		parts := strings.Split(rel, string(os.PathSeparator))
		if len(parts) < 2 || strings.Contains(rel, "..") {
			continue
		}
		target := filepath.Join(dst, filepath.Join(parts[1:]...))
		if !strings.HasPrefix(target, filepath.Clean(dst)+string(os.PathSeparator)) {
			return fmt.Errorf("ruta insegura: %s", h.Name)
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, os.FileMode(h.Mode)&0777); err != nil {
				return err
			}
		} else if h.Typeflag == tar.TypeReg {
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode)&0777)
			if err != nil {
				return err
			}
			_, e := io.Copy(out, tr)
			ce := out.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		}
	}
	return nil
}

func readOSName() string {
	b, e := os.ReadFile("/etc/os-release")
	if e != nil {
		return runtime.GOOS
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), "\"")
		}
	}
	return runtime.GOOS
}
func readRAMMB() uint64 {
	b, e := os.ReadFile("/proc/meminfo")
	if e != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "MemTotal:" {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			return v / 1024
		}
	}
	return 0
}
func readFreeDiskGB(path string) uint64 {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return 0
	}
	return st.Bavail * uint64(st.Bsize) / (1024 * 1024 * 1024)
}
func commandExists(n string) bool { _, e := exec.LookPath(n); return e == nil }
func fileExists(p string) bool    { _, e := os.Lstat(p); return e == nil }
