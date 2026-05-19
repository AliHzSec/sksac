package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const version = "1.0.0"

const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiReset  = "\x1b[0m"
)

const banner = `
   _____    __ __   _____    ___    ______
  / ___/   / //_/  / ___/   /   |  / ____/
  \__ \   / ,<     \__ \   / /| | / /     
 ___/ /  / /| |   ___/ /  / ___ |/ /___   
/____/  /_/ |_|  /____/  /_/  |_|\____/

  v` + version + ` - github.com/AliHzSec
`

// POSIX / IEEE 1003.1-2001 username regex
// Must start with a letter or underscore, followed by letters, digits, dash, underscore
// Optionally ends with $
var usernameRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_\-]{0,31}\$?$`)

type Options struct {
	IdentityFile  string
	Host          string
	HostList      string
	Username      string
	UsernameList  string
	Threads       int
	AccessOnly    bool
	Silent        bool
	OutputEnabled bool
	OutputPath    string
	Debug         bool
	NoColor       bool
}

type Target struct {
	Host     string
	Port     string
	Username string
}

type Stats struct {
	total     int64
	checked   int64
	found     int64
	errors    int64
	startTime time.Time
}

func (s *Stats) increment() { atomic.AddInt64(&s.checked, 1) }
func (s *Stats) addFound()  { atomic.AddInt64(&s.found, 1) }
func (s *Stats) addError()  { atomic.AddInt64(&s.errors, 1) }

func printBanner() {
	fmt.Print(banner)
}

func printConfig(opts *Options, totalTargets int) {
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf(":: Identity File    : %s\n", opts.IdentityFile)
	if opts.Host != "" {
		fmt.Printf(":: Host             : %s\n", opts.Host)
	}
	if opts.HostList != "" {
		fmt.Printf(":: Host List        : %s\n", opts.HostList)
	}
	if opts.Username != "" {
		fmt.Printf(":: Username         : %s\n", opts.Username)
	}
	if opts.UsernameList != "" {
		fmt.Printf(":: Username List    : %s\n", opts.UsernameList)
	}
	fmt.Printf(":: Total Targets    : %d\n", totalTargets)
	fmt.Printf(":: Threads          : %d\n", opts.Threads)
	fmt.Printf(":: Access Only      : %v\n", opts.AccessOnly)
	if opts.OutputEnabled {
		dir := opts.OutputPath
		if dir == "" {
			dir = "."
		}
		fmt.Printf(":: Output           : %s\n", dir)
	}
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println()
}

func checkKeyPermissions(keyPath string) error {
	info, err := os.Stat(keyPath)
	if err != nil {
		return fmt.Errorf("cannot access key file: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		return fmt.Errorf("incorrect permissions on SSH key file '%s' (got %o, need 600)\n  Fix with: chmod 600 %s", keyPath, mode, keyPath)
	}
	return nil
}

// parseHost parses "host" or "host:port" and returns (host, port)
func parseHost(input string) (string, string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", fmt.Errorf("empty host")
	}

	// Try to split host:port
	host, port, err := net.SplitHostPort(input)
	if err == nil {
		// Validate port
		if port == "" {
			port = "22"
		}
		return host, port, nil
	}

	// No port specified — use default 22
	// Could be plain IP or domain
	return input, "22", nil
}

// sanitizeUsername returns true if username is valid POSIX
func sanitizeUsername(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" {
		return false
	}
	return usernameRegex.MatchString(u)
}

// loadHosts loads and parses hosts from a file, returns []struct{host, port}
func loadHosts(path string) ([]struct{ host, port string }, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open host list: %v", err)
	}
	defer f.Close()

	seen := make(map[string]bool)
	var hosts []struct{ host, port string }

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, p, err := parseHost(line)
		if err != nil {
			continue
		}
		key := h + ":" + p
		if seen[key] {
			continue
		}
		seen[key] = true
		hosts = append(hosts, struct{ host, port string }{h, p})
	}
	return hosts, scanner.Err()
}

// loadUsernames loads and sanitizes usernames from a file
func loadUsernames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open username list: %v", err)
	}
	defer f.Close()

	seen := make(map[string]bool)
	var users []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !sanitizeUsername(line) {
			continue
		}
		normalized := line
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		users = append(users, normalized)
	}
	sort.Strings(users)
	return users, scanner.Err()
}

// resolveHost resolves a hostname using the system default resolver
func resolveHost(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for %s", host)
	}
	return addrs[0], nil
}

// checkSSHAccess attempts SSH connection and returns true if access is granted
func checkSSHAccess(target Target, keyPath string, debug bool) (bool, error) {
	addr := target.Host + ":" + target.Port

	args := []string{
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-p", target.Port,
		"-T",
		fmt.Sprintf("%s@%s", target.Username, target.Host),
		"exit",
	}

	cmd := exec.Command("ssh", args...)
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if debug {
		fmt.Printf("[DEBUG] ssh %s@%s:%s\n", target.Username, target.Host, target.Port)
		if outputStr != "" {
			fmt.Printf("[DEBUG]   %s\n", outputStr)
		}
	}

	_ = addr

	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok {
			// exit code 255 = SSH error (connection refused, permission denied, etc.)
			// exit code 1 = remote command failed (but connected!)
			// exit code 0 = success
			exitCode := exitErr.ExitCode()
			if exitCode == 1 {
				// Connected but 'exit' returned 1 — still means we have access
				return true, nil
			}
		}
		// Permission denied or connection error
		if strings.Contains(outputStr, "Permission denied") ||
			strings.Contains(outputStr, "publickey") {
			return false, nil
		}
		// Connection timeout/refused — treat as error
		return false, nil
	}

	// exit code 0 = connected and exited cleanly
	return true, nil
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%d:%02d:%02d", h, m, s)
}

func run(opts *Options) error {
	if err := checkKeyPermissions(opts.IdentityFile); err != nil {
		return err
	}

	// Load hosts
	type hostEntry struct{ host, port string }
	var hostEntries []hostEntry

	if opts.Host != "" {
		h, p, err := parseHost(opts.Host)
		if err != nil {
			return fmt.Errorf("invalid host: %v", err)
		}
		hostEntries = append(hostEntries, hostEntry{h, p})
	} else {
		loaded, err := loadHosts(opts.HostList)
		if err != nil {
			return err
		}
		for _, e := range loaded {
			hostEntries = append(hostEntries, hostEntry{e.host, e.port})
		}
		gologger.Info().Msgf("Loaded %d hosts from list", len(hostEntries))
	}

	if len(hostEntries) == 0 {
		return fmt.Errorf("no valid hosts to check")
	}

	// Load usernames
	var usernames []string
	if opts.Username != "" {
		if !sanitizeUsername(opts.Username) {
			return fmt.Errorf("invalid username: %s", opts.Username)
		}
		usernames = []string{opts.Username}
	} else {
		loaded, err := loadUsernames(opts.UsernameList)
		if err != nil {
			return err
		}
		usernames = loaded
		gologger.Info().Msgf("Loaded %d usernames from list", len(usernames))
	}

	if len(usernames) == 0 {
		return fmt.Errorf("no valid usernames to check")
	}

	// Resolve hostnames
	gologger.Info().Msgf("Resolving hosts...")
	type resolvedHost struct {
		original string
		resolved string
		port     string
	}
	var resolvedHosts []resolvedHost
	for _, e := range hostEntries {
		ip, err := resolveHost(e.host)
		if err != nil {
			gologger.Warning().Msgf("Could not resolve %s: %v — skipping", e.host, err)
			continue
		}
		resolvedHosts = append(resolvedHosts, resolvedHost{e.host, ip, e.port})
	}

	if len(resolvedHosts) == 0 {
		return fmt.Errorf("no hosts could be resolved")
	}

	// Build all targets (cartesian product: hosts × usernames)
	var targets []Target
	for _, rh := range resolvedHosts {
		for _, u := range usernames {
			targets = append(targets, Target{
				Host:     rh.resolved,
				Port:     rh.port,
				Username: u,
			})
		}
	}

	totalTargets := int64(len(targets))

	// Setup output file
	var outputFile *os.File
	if opts.OutputEnabled {
		outDir := opts.OutputPath
		if outDir == "" {
			var err error
			outDir, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("cannot determine current directory: %v", err)
			}
		}
		ts := time.Now().Format("20060102_150405")
		outName := fmt.Sprintf("access_found_%s.txt", ts)
		outPath := filepath.Join(outDir, outName)
		var err error
		outputFile, err = os.Create(outPath)
		if err != nil {
			return fmt.Errorf("cannot create output file: %v", err)
		}
		defer outputFile.Close()
		gologger.Info().Msgf("Output file: %s", outPath)
	}

	// Print config
	if !opts.Silent {
		printConfig(opts, len(targets))
	}

	// Setup stats
	stats := &Stats{
		total:     totalTargets,
		startTime: time.Now(),
	}

	// Progress printer
	var printMu sync.Mutex

	drawProgress := func() {
		checked := atomic.LoadInt64(&stats.checked)
		found := atomic.LoadInt64(&stats.found)
		elapsed := time.Since(stats.startTime)
		fmt.Printf("\r\x1b[2K:: Progress: [%d/%d] :: Found: %d :: Duration: [%s] :: Errors: %d ::",
			checked, totalTargets, found,
			formatDuration(elapsed),
			atomic.LoadInt64(&stats.errors),
		)
	}

	stopProgress := make(chan struct{})
	var progressWg sync.WaitGroup
	if !opts.Silent {
		progressWg.Add(1)
		go func() {
			defer progressWg.Done()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-ticker.C:
					printMu.Lock()
					drawProgress()
					printMu.Unlock()
				}
			}
		}()
	}

	// Ctrl+C handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Print("\r\x1b[2K")
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		gologger.Warning().Msg("Caught keyboard interrupt (Ctrl-C)")
		if outputFile != nil {
			outputFile.Close()
		}
		os.Exit(1)
	}()

	// Worker pool
	jobs := make(chan Target, opts.Threads*2)
	var wg sync.WaitGroup

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				hasAccess, err := checkSSHAccess(target, opts.IdentityFile, opts.Debug)
				stats.increment()

				if err != nil {
					stats.addError()
					continue
				}

				line := fmt.Sprintf("%s@%s:%s", target.Username, target.Host, target.Port)

				if hasAccess {
					stats.addFound()
					printMu.Lock()
					if !opts.NoColor {
						fmt.Printf("\r\x1b[2K"+ansiGreen+"%s"+ansiReset+"\n", line)
					} else {
						fmt.Printf("\r\x1b[2K%s\n", line)
					}
					if !opts.Silent {
						drawProgress()
					}
					if outputFile != nil {
						fmt.Fprintln(outputFile, line)
					}
					printMu.Unlock()
				} else if !opts.AccessOnly {
					printMu.Lock()
					if !opts.NoColor {
						fmt.Printf("\r\x1b[2K"+ansiYellow+"%s"+ansiReset+"\n", line)
					} else {
						fmt.Printf("\r\x1b[2K%s\n", line)
					}
					if !opts.Silent {
						drawProgress()
					}
					printMu.Unlock()
				}
			}
		}()
	}

	// Feed jobs
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()

	if !opts.Silent {
		close(stopProgress)
		progressWg.Wait()
		elapsed := time.Since(stats.startTime)
		fmt.Printf("\r\x1b[2K:: Progress: [%d/%d] :: Found: %d :: Duration: [%s] :: Errors: %d ::\n",
			atomic.LoadInt64(&stats.checked),
			totalTargets,
			atomic.LoadInt64(&stats.found),
			formatDuration(elapsed),
			atomic.LoadInt64(&stats.errors),
		)
		fmt.Println()
		fmt.Printf("[*] Scan complete. Found %d accessible targets.\n", atomic.LoadInt64(&stats.found))
	}

	return nil
}

func main() {
	opts := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("sksac - SSH Key Server Access Checker")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&opts.IdentityFile, "identity-file", "i", "", "Path to SSH private key"),
		flagSet.StringVarP(&opts.Host, "host", "h", "", "Single target host (e.g. 1.1.1.1 or host.com:2222)"),
		flagSet.StringVarP(&opts.HostList, "host-list", "hl", "", "File with one host per line"),
		flagSet.StringVarP(&opts.Username, "username", "u", "", "Single SSH username"),
		flagSet.StringVarP(&opts.UsernameList, "username-list", "ul", "", "File with one username per line"),
	)

	flagSet.CreateGroup("enumeration", "Enumeration",
		flagSet.IntVarP(&opts.Threads, "threads", "t", 10, "Number of concurrent threads"),
		flagSet.BoolVarP(&opts.AccessOnly, "access-only", "a", false, "Only show hosts with access"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "Silent mode"),
		flagSet.BoolVarP(&opts.OutputEnabled, "output", "o", false, "Save results to file"),
		flagSet.StringVarP(&opts.OutputPath, "output-path", "op", "", "Directory to save output file (use with -o)"),
		flagSet.BoolVarP(&opts.Debug, "debug", "d", false, "Show raw SSH output"),
		flagSet.BoolVarP(&opts.NoColor, "no-color", "nc", false, "Disable colors in output"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Error parsing flags: %v", err)
	}

	if opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		printBanner()
	}

	// Validate required flags
	if opts.IdentityFile == "" {
		gologger.Fatal().Msg("Flag -i / -identity-file is required")
	}

	// Resolve ~ in path
	if strings.HasPrefix(opts.IdentityFile, "~/") {
		home, _ := os.UserHomeDir()
		opts.IdentityFile = filepath.Join(home, opts.IdentityFile[2:])
	}

	// -h and -hl are mutually exclusive, one is required
	if opts.Host != "" && opts.HostList != "" {
		gologger.Fatal().Msg("Flags -h / -host and -hl / -host-list are mutually exclusive")
	}
	if opts.Host == "" && opts.HostList == "" {
		gologger.Fatal().Msg("Either -h / -host or -hl / -host-list is required")
	}

	// -u and -ul are mutually exclusive, one is required
	if opts.Username != "" && opts.UsernameList != "" {
		gologger.Fatal().Msg("Flags -u / -username and -ul / -username-list are mutually exclusive")
	}
	if opts.Username == "" && opts.UsernameList == "" {
		gologger.Fatal().Msg("Either -u / -username or -ul / -username-list is required")
	}

	if opts.Threads <= 0 {
		opts.Threads = 10
	}

	if err := run(opts); err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}
