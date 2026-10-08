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
	// Fail closed: no se ejecuta install.sh si el sistema no es compatible
	// o cualquier puerto predeterminado está ocupado.
	if !r.systemd {
		fmt.Println("\nNO SE PUEDE CONTINUAR")
		fmt.Println("systemd no está disponible en este servidor.")
		fmt.Println("No se realizaron cambios en el servidor.")
		return 1
	}
	var occupied []installerPort
	for _, p := range r.ports {
		if !p.free {
			occupied = append(occupied, p)
		}
	}
	if len(occupied) > 0 {
		fmt.Println("\nNO SE PUEDE CONTINUAR")
		fmt.Println("Libere los puertos marcados antes de continuar.")
		fmt.Println("No se detendrán servicios existentes.")
		fmt.Println("No se realizaron cambios en el servidor.")
		return 1
	}

	fmt.Println("\n[3/3] Validación completada.")
	fmt.Println("[✓] Puertos predeterminados disponibles.")
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
	}{{"TCP", 80}, {"TCP", 443}, {"TCP", 8080}, {"TCP", 7300}, {"TCP", 8880}, {"TCP", 10086}} {
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
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║          CONECTA SSH-PRO             ║")
	fmt.Println("║          INSTALADOR                  ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println("\n[1/3] Verificando sistema...")
	fmt.Printf("[✓] %s · %s\n", r.os, r.arch)
	if r.systemd {
		fmt.Println("[✓] systemd disponible")
	} else {
		fmt.Println("[✗] systemd no disponible")
	}
	fmt.Println("\n[2/3] Verificando puertos...")
	labels := map[int]string{
		80:    "SSH WebSocket / BHTTP",
		443:   "TLS TUNNEL",
		8080:  "SSH WebSocket / BHTTP",
		7300:  "UDPGW",
		8880:  "HCR",
		10086: "XRAY nativo",
	}
	for _, p := range r.ports {
		state := "[✓]"
		detail := "disponible"
		if !p.free {
			state = "[✗]"
			detail = "OCUPADO"
			if p.owner != "" {
				detail += " · " + p.owner
			}
		}
		fmt.Printf("%s %-23s TCP/%d · %s\n", state, labels[p.port], p.port, detail)
	}
}

func inspectPort(proto string, port int) installerPort {
	p := installerPort{protocol: proto, port: port, free: true}
	flag := "-H -ltnp"
	network := "tcp"
	if proto == "UDP" {
		flag = "-H -lunp"
		network = "udp"
	}
	// Inspectar sockets existentes primero: esto también detecta listeners IPv6
	// y sockets ligados a direcciones concretas que el bind IPv4 podría omitir.
	if commandExists("ss") {
		args := strings.Fields(flag)
		out, err := exec.Command("ss", append(args, fmt.Sprintf("sport = :%d", port))...).CombinedOutput()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			p.free = false
			p.owner = findPortOwner(proto, port)
			return p
		}
	}
	address := net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
	if proto == "UDP" {
		pc, err := net.ListenPacket("udp", address)
		if err == nil {
			_ = pc.Close()
			return p
		}
	} else {
		ln, err := net.Listen(network, address)
		if err == nil {
			_ = ln.Close()
			return p
		}
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
	out, err := exec.Command("ss", "-H", flag, fmt.Sprintf("sport = :%d", port)).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		marker := "users:((\""
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		rest := line[i+len(marker):]
		end := strings.Index(rest, "\"")
		if end < 0 {
			continue
		}
		name := rest[:end]
		pid := ""
		if j := strings.Index(rest, "pid="); j >= 0 {
			value := rest[j+len("pid="):]
			if k := strings.IndexAny(value, ",)"); k >= 0 {
				pid = value[:k]
			}
		}
		if pid != "" {
			return fmt.Sprintf("%s (PID %s)", name, pid)
		}
		return name
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
