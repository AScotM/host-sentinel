package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "1.0.0"

type Severity int

const (
	SeverityNormal Severity = iota
	SeverityNotice
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityNormal:
		return "NORMAL"
	case SeverityNotice:
		return "NOTICE"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type CPUStats struct {
	Load1          float64  `json:"load_1"`
	Load5          float64  `json:"load_5"`
	Load15         float64  `json:"load_15"`
	LogicalCPUs    int      `json:"logical_cpus"`
	LoadPerCPU     float64  `json:"load_per_cpu"`
	PressureSome10 float64  `json:"pressure_some_avg10"`
	PressureFull10 float64  `json:"pressure_full_avg10"`
	Severity       Severity `json:"severity"`
}

type MemoryStats struct {
	TotalBytes       uint64   `json:"total_bytes"`
	AvailableBytes   uint64   `json:"available_bytes"`
	UsedBytes        uint64   `json:"used_bytes"`
	UsedPercent      float64  `json:"used_percent"`
	SwapTotalBytes   uint64   `json:"swap_total_bytes"`
	SwapFreeBytes    uint64   `json:"swap_free_bytes"`
	SwapUsedBytes    uint64   `json:"swap_used_bytes"`
	SwapUsedPercent  float64  `json:"swap_used_percent"`
	PressureSome10   float64  `json:"pressure_some_avg10"`
	PressureFull10   float64  `json:"pressure_full_avg10"`
	Severity         Severity `json:"severity"`
}

type FilesystemStats struct {
	Path         string   `json:"path"`
	TotalBytes   uint64   `json:"total_bytes"`
	FreeBytes    uint64   `json:"free_bytes"`
	UsedBytes    uint64   `json:"used_bytes"`
	UsedPercent  float64  `json:"used_percent"`
	TotalInodes  uint64   `json:"total_inodes"`
	FreeInodes   uint64   `json:"free_inodes"`
	UsedInodes   uint64   `json:"used_inodes"`
	InodePercent float64  `json:"inode_used_percent"`
	Severity     Severity `json:"severity"`
}

type ProcessStats struct {
	Total         int      `json:"total"`
	Running       int      `json:"running"`
	Sleeping      int      `json:"sleeping"`
	DiskSleep     int      `json:"disk_sleep"`
	Stopped       int      `json:"stopped"`
	Zombie        int      `json:"zombie"`
	Other         int      `json:"other"`
	Severity      Severity `json:"severity"`
}

type NetworkInterface struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	RXBytes    uint64 `json:"rx_bytes"`
	TXBytes    uint64 `json:"tx_bytes"`
	RXPackets  uint64 `json:"rx_packets"`
	TXPackets  uint64 `json:"tx_packets"`
	RXErrors   uint64 `json:"rx_errors"`
	TXErrors   uint64 `json:"tx_errors"`
	RXDropped  uint64 `json:"rx_dropped"`
	TXDropped  uint64 `json:"tx_dropped"`
}

type NetworkStats struct {
	Interfaces    []NetworkInterface `json:"interfaces"`
	TCPIPv4       int                `json:"tcp_ipv4"`
	TCPIPv6       int                `json:"tcp_ipv6"`
	UDPIPv4       int                `json:"udp_ipv4"`
	UDPIPv6       int                `json:"udp_ipv6"`
	UnixSockets   int                `json:"unix_sockets"`
	Netlink       int                `json:"netlink_sockets"`
	SocketUsed    uint64             `json:"sockets_used"`
	TCPInUse      uint64             `json:"tcp_in_use"`
	TCPTimeWait   uint64             `json:"tcp_time_wait"`
	TCPAllocated  uint64             `json:"tcp_allocated"`
	UDPInUse      uint64             `json:"udp_in_use"`
	Severity      Severity           `json:"severity"`
}

type SELinuxStats struct {
	Available bool     `json:"available"`
	Enabled   bool     `json:"enabled"`
	Enforcing bool     `json:"enforcing"`
	Mode      string   `json:"mode"`
	Severity  Severity `json:"severity"`
}

type HostStats struct {
	Hostname     string `json:"hostname"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	Uptime       uint64 `json:"uptime_seconds"`
	BootTime     string `json:"boot_time"`
}

type Snapshot struct {
	Version     string            `json:"version"`
	Timestamp   string            `json:"timestamp"`
	Host        HostStats         `json:"host"`
	CPU         CPUStats          `json:"cpu"`
	Memory      MemoryStats       `json:"memory"`
	Filesystems []FilesystemStats `json:"filesystems"`
	Processes   ProcessStats      `json:"processes"`
	Network     NetworkStats      `json:"network"`
	SELinux     SELinuxStats      `json:"selinux"`
	Overall     Severity          `json:"overall"`
}

type Drift struct {
	Metric   string   `json:"metric"`
	Baseline string   `json:"baseline"`
	Current  string   `json:"current"`
	Severity Severity `json:"severity"`
}

type Report struct {
	Snapshot Snapshot `json:"snapshot"`
	Drift    []Drift  `json:"drift,omitempty"`
}

type Config struct {
	JSON         bool
	Watch        time.Duration
	BaselineFile string
	CompareFile  string
	Filesystems  []string
}

func main() {
	config, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if config.Watch > 0 && config.BaselineFile != "" {
		fmt.Fprintln(os.Stderr, "Error: --watch cannot be combined with --baseline")
		os.Exit(1)
	}

	ctx := make(chan os.Signal, 1)
	signal.Notify(ctx, os.Interrupt, syscall.SIGTERM)

	if config.Watch > 0 {
		runWatch(config, ctx)
		return
	}

	report, err := createReport(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if config.BaselineFile != "" {
		if err := saveBaseline(config.BaselineFile, report.Snapshot); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

		if config.JSON {
			printJSON(report)
		} else {
			printHuman(report)
			fmt.Printf("\nBaseline written to %s\n", config.BaselineFile)
		}
		return
	}

	if config.JSON {
		printJSON(report)
	} else {
		printHuman(report)
	}
}

func parseFlags() (Config, error) {
	var config Config
	var watchSeconds float64
	var filesystemList string
	var showVersion bool

	flag.BoolVar(&config.JSON, "json", false, "")
	flag.Float64Var(&watchSeconds, "watch", 0, "")
	flag.StringVar(&config.BaselineFile, "baseline", "", "")
	flag.StringVar(&config.CompareFile, "compare", "", "")
	flag.StringVar(&filesystemList, "filesystems", "/,/var,/home", "")
	flag.BoolVar(&showVersion, "version", false, "")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Host Sentinel %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [OPTIONS]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --json\n")
		fmt.Fprintf(os.Stderr, "  --watch SECONDS\n")
		fmt.Fprintf(os.Stderr, "  --baseline FILE\n")
		fmt.Fprintf(os.Stderr, "  --compare FILE\n")
		fmt.Fprintf(os.Stderr, "  --filesystems PATHS\n")
		fmt.Fprintf(os.Stderr, "  --version\n")
		fmt.Fprintf(os.Stderr, "  --help\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  %s --json\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  %s --watch 2\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  %s --baseline baseline.json\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  %s --compare baseline.json\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  %s --filesystems /,/var,/home,/srv\n", filepath.Base(os.Args[0]))
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("Host Sentinel %s\n", version)
		os.Exit(0)
	}

	if flag.NArg() != 0 {
		return config, fmt.Errorf("unexpected argument: %s", flag.Arg(0))
	}

	if watchSeconds < 0 {
		return config, errors.New("--watch must be greater than zero")
	}

	if watchSeconds > 0 {
		config.Watch = time.Duration(watchSeconds * float64(time.Second))
		if config.Watch < 100*time.Millisecond {
			return config, errors.New("--watch interval must be at least 0.1 seconds")
		}
	}

	if config.BaselineFile != "" && config.CompareFile != "" {
		return config, errors.New("--baseline and --compare cannot be used together")
	}

	for _, path := range strings.Split(filesystemList, ",") {
		path = strings.TrimSpace(path)
		if path != "" {
			config.Filesystems = append(config.Filesystems, path)
		}
	}

	if len(config.Filesystems) == 0 {
		config.Filesystems = []string{"/"}
	}

	return config, nil
}

func runWatch(config Config, signals <-chan os.Signal) {
	ticker := time.NewTicker(config.Watch)
	defer ticker.Stop()

	for {
		report, err := createReport(config)

		if config.JSON {
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			} else {
				printJSON(report)
			}
		} else {
			fmt.Print("\033[H\033[2J")
			if err != nil {
				fmt.Printf("Host Sentinel\n=============\n\nError: %v\n", err)
			} else {
				printHuman(report)
			}
		}

		select {
		case <-ticker.C:
		case <-signals:
			if !config.JSON {
				fmt.Println()
			}
			return
		}
	}
}

func createReport(config Config) (Report, error) {
	var report Report

	host, err := readHostStats()
	if err != nil {
		return report, err
	}

	cpu, err := readCPUStats()
	if err != nil {
		return report, err
	}

	memory, err := readMemoryStats()
	if err != nil {
		return report, err
	}

	filesystems := readFilesystems(config.Filesystems)
	processes := readProcessStats()
	network := readNetworkStats()
	selinux := readSELinuxStats()

	snapshot := Snapshot{
		Version:     version,
		Timestamp:   time.Now().Format(time.RFC3339),
		Host:        host,
		CPU:         cpu,
		Memory:      memory,
		Filesystems: filesystems,
		Processes:   processes,
		Network:     network,
		SELinux:     selinux,
	}

	snapshot.Overall = calculateOverall(snapshot)
	report.Snapshot = snapshot

	if config.CompareFile != "" {
		baseline, err := loadBaseline(config.CompareFile)
		if err != nil {
			return report, err
		}
		report.Drift = compareSnapshots(baseline, snapshot)
	}

	return report, nil
}

func readHostStats() (HostStats, error) {
	var stats HostStats

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	kernelBytes, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return stats, fmt.Errorf("cannot read kernel version: %w", err)
	}

	uptimeBytes, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return stats, fmt.Errorf("cannot read uptime: %w", err)
	}

	uptimeFields := strings.Fields(string(uptimeBytes))
	if len(uptimeFields) == 0 {
		return stats, errors.New("invalid /proc/uptime")
	}

	uptimeFloat, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return stats, fmt.Errorf("invalid uptime value: %w", err)
	}

	uptime := uint64(uptimeFloat)

	stats = HostStats{
		Hostname:     hostname,
		Kernel:       strings.TrimSpace(string(kernelBytes)),
		Architecture: runtime.GOARCH,
		Uptime:       uptime,
		BootTime:     time.Now().Add(-time.Duration(uptime) * time.Second).Format(time.RFC3339),
	}

	return stats, nil
}

func readCPUStats() (CPUStats, error) {
	var stats CPUStats

	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return stats, fmt.Errorf("cannot read /proc/loadavg: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return stats, errors.New("invalid /proc/loadavg")
	}

	stats.Load1, _ = strconv.ParseFloat(fields[0], 64)
	stats.Load5, _ = strconv.ParseFloat(fields[1], 64)
	stats.Load15, _ = strconv.ParseFloat(fields[2], 64)
	stats.LogicalCPUs = runtime.NumCPU()

	if stats.LogicalCPUs > 0 {
		stats.LoadPerCPU = stats.Load1 / float64(stats.LogicalCPUs)
	}

	stats.PressureSome10, stats.PressureFull10 = readPressure("/proc/pressure/cpu")
	stats.Severity = evaluateCPU(stats)

	return stats, nil
}

func readMemoryStats() (MemoryStats, error) {
	var stats MemoryStats

	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return stats, fmt.Errorf("cannot read /proc/meminfo: %w", err)
	}
	defer file.Close()

	values := make(map[string]uint64)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		values[key] = value * 1024
	}

	if err := scanner.Err(); err != nil {
		return stats, err
	}

	stats.TotalBytes = values["MemTotal"]
	stats.AvailableBytes = values["MemAvailable"]

	if stats.TotalBytes >= stats.AvailableBytes {
		stats.UsedBytes = stats.TotalBytes - stats.AvailableBytes
	}

	if stats.TotalBytes > 0 {
		stats.UsedPercent = float64(stats.UsedBytes) / float64(stats.TotalBytes) * 100
	}

	stats.SwapTotalBytes = values["SwapTotal"]
	stats.SwapFreeBytes = values["SwapFree"]

	if stats.SwapTotalBytes >= stats.SwapFreeBytes {
		stats.SwapUsedBytes = stats.SwapTotalBytes - stats.SwapFreeBytes
	}

	if stats.SwapTotalBytes > 0 {
		stats.SwapUsedPercent = float64(stats.SwapUsedBytes) / float64(stats.SwapTotalBytes) * 100
	}

	stats.PressureSome10, stats.PressureFull10 = readPressure("/proc/pressure/memory")
	stats.Severity = evaluateMemory(stats)

	return stats, nil
}

func readPressure(path string) (float64, float64) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	var some float64
	var full float64

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		kind := fields[0]

		for _, field := range fields[1:] {
			if !strings.HasPrefix(field, "avg10=") {
				continue
			}

			value, err := strconv.ParseFloat(strings.TrimPrefix(field, "avg10="), 64)
			if err != nil {
				continue
			}

			switch kind {
			case "some":
				some = value
			case "full":
				full = value
			}
		}
	}

	return some, full
}

func readFilesystems(paths []string) []FilesystemStats {
	seen := make(map[string]bool)
	var result []FilesystemStats

	for _, path := range paths {
		clean := filepath.Clean(path)

		if seen[clean] {
			continue
		}
		seen[clean] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(clean, &stat); err != nil {
			continue
		}

		blockSize := uint64(stat.Bsize)
		total := stat.Blocks * blockSize
		free := stat.Bavail * blockSize
		var used uint64

		if total >= free {
			used = total - free
		}

		var usedPercent float64
		if total > 0 {
			usedPercent = float64(used) / float64(total) * 100
		}

		totalInodes := stat.Files
		freeInodes := stat.Ffree
		var usedInodes uint64

		if totalInodes >= freeInodes {
			usedInodes = totalInodes - freeInodes
		}

		var inodePercent float64
		if totalInodes > 0 {
			inodePercent = float64(usedInodes) / float64(totalInodes) * 100
		}

		fs := FilesystemStats{
			Path:         clean,
			TotalBytes:   total,
			FreeBytes:    free,
			UsedBytes:    used,
			UsedPercent:  usedPercent,
			TotalInodes:  totalInodes,
			FreeInodes:   freeInodes,
			UsedInodes:   usedInodes,
			InodePercent: inodePercent,
		}

		fs.Severity = evaluateFilesystem(fs)
		result = append(result, fs)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Path < result[j].Path
	})

	return result
}

func readProcessStats() ProcessStats {
	var stats ProcessStats

	entries, err := os.ReadDir("/proc")
	if err != nil {
		stats.Severity = SeverityNotice
		return stats
	}

	for _, entry := range entries {
		if !entry.IsDir() || !isPID(entry.Name()) {
			continue
		}

		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}

		state, ok := parseProcessState(string(data))
		if !ok {
			continue
		}

		stats.Total++

		switch state {
		case "R":
			stats.Running++
		case "S", "I":
			stats.Sleeping++
		case "D":
			stats.DiskSleep++
		case "T", "t":
			stats.Stopped++
		case "Z":
			stats.Zombie++
		default:
			stats.Other++
		}
	}

	stats.Severity = evaluateProcesses(stats)
	return stats
}

func isPID(value string) bool {
	if value == "" {
		return false
	}

	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

func parseProcessState(stat string) (string, bool) {
	index := strings.LastIndex(stat, ")")
	if index == -1 || index+2 >= len(stat) {
		return "", false
	}

	rest := strings.TrimSpace(stat[index+1:])
	fields := strings.Fields(rest)

	if len(fields) == 0 {
		return "", false
	}

	return fields[0], true
}

func readNetworkStats() NetworkStats {
	var stats NetworkStats

	entries, err := os.ReadDir("/sys/class/net")
	if err == nil {
		for _, entry := range entries {
			name := entry.Name()
			base := filepath.Join("/sys/class/net", name)

			iface := NetworkInterface{
				Name:      name,
				State:     readTrimmed(filepath.Join(base, "operstate")),
				RXBytes:   readUint(filepath.Join(base, "statistics", "rx_bytes")),
				TXBytes:   readUint(filepath.Join(base, "statistics", "tx_bytes")),
				RXPackets: readUint(filepath.Join(base, "statistics", "rx_packets")),
				TXPackets: readUint(filepath.Join(base, "statistics", "tx_packets")),
				RXErrors:  readUint(filepath.Join(base, "statistics", "rx_errors")),
				TXErrors:  readUint(filepath.Join(base, "statistics", "tx_errors")),
				RXDropped: readUint(filepath.Join(base, "statistics", "rx_dropped")),
				TXDropped: readUint(filepath.Join(base, "statistics", "tx_dropped")),
			}

			stats.Interfaces = append(stats.Interfaces, iface)
		}
	}

	sort.Slice(stats.Interfaces, func(i, j int) bool {
		return stats.Interfaces[i].Name < stats.Interfaces[j].Name
	})

	stats.TCPIPv4 = countProcTable("/proc/net/tcp")
	stats.TCPIPv6 = countProcTable("/proc/net/tcp6")
	stats.UDPIPv4 = countProcTable("/proc/net/udp")
	stats.UDPIPv6 = countProcTable("/proc/net/udp6")
	stats.UnixSockets = countProcTable("/proc/net/unix")
	stats.Netlink = countProcTable("/proc/net/netlink")

	readSockstat(&stats)
	stats.Severity = evaluateNetwork(stats)

	return stats
}

func countProcTable(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := -1

	for scanner.Scan() {
		count++
	}

	if count < 0 {
		return 0
	}

	return count
}

func readSockstat(stats *NetworkStats) {
	file, err := os.Open("/proc/net/sockstat")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		switch fields[0] {
		case "sockets:":
			for i := 1; i+1 < len(fields); i += 2 {
				if fields[i] == "used" {
					stats.SocketUsed, _ = strconv.ParseUint(fields[i+1], 10, 64)
				}
			}
		case "TCP:":
			for i := 1; i+1 < len(fields); i += 2 {
				value, _ := strconv.ParseUint(fields[i+1], 10, 64)

				switch fields[i] {
				case "inuse":
					stats.TCPInUse = value
				case "tw":
					stats.TCPTimeWait = value
				case "alloc":
					stats.TCPAllocated = value
				}
			}
		case "UDP:":
			for i := 1; i+1 < len(fields); i += 2 {
				if fields[i] == "inuse" {
					stats.UDPInUse, _ = strconv.ParseUint(fields[i+1], 10, 64)
				}
			}
		}
	}
}

func readSELinuxStats() SELinuxStats {
	var stats SELinuxStats

	enforcePath := "/sys/fs/selinux/enforce"

	if _, err := os.Stat("/sys/fs/selinux"); err != nil {
		stats.Mode = "unavailable"
		stats.Severity = SeverityNotice
		return stats
	}

	stats.Available = true

	data, err := os.ReadFile(enforcePath)
	if err != nil {
		stats.Mode = "unknown"
		stats.Severity = SeverityNotice
		return stats
	}

	stats.Enabled = true

	switch strings.TrimSpace(string(data)) {
	case "1":
		stats.Enforcing = true
		stats.Mode = "enforcing"
		stats.Severity = SeverityNormal
	case "0":
		stats.Enforcing = false
		stats.Mode = "permissive"
		stats.Severity = SeverityNotice
	default:
		stats.Mode = "unknown"
		stats.Severity = SeverityNotice
	}

	return stats
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}

	return strings.TrimSpace(string(data))
}

func readUint(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}

	return value
}

func evaluateCPU(stats CPUStats) Severity {
	switch {
	case stats.LoadPerCPU >= 2.0 || stats.PressureFull10 >= 20:
		return SeverityCritical
	case stats.LoadPerCPU >= 1.25 || stats.PressureSome10 >= 50 || stats.PressureFull10 >= 10:
		return SeverityWarning
	case stats.LoadPerCPU >= 0.8 || stats.PressureSome10 >= 20:
		return SeverityNotice
	default:
		return SeverityNormal
	}
}

func evaluateMemory(stats MemoryStats) Severity {
	switch {
	case stats.UsedPercent >= 95 || stats.PressureFull10 >= 20:
		return SeverityCritical
	case stats.UsedPercent >= 90 || stats.SwapUsedPercent >= 75 || stats.PressureFull10 >= 10:
		return SeverityWarning
	case stats.UsedPercent >= 80 || stats.SwapUsedPercent >= 40 || stats.PressureSome10 >= 20:
		return SeverityNotice
	default:
		return SeverityNormal
	}
}

func evaluateFilesystem(stats FilesystemStats) Severity {
	maxUsage := stats.UsedPercent
	if stats.InodePercent > maxUsage {
		maxUsage = stats.InodePercent
	}

	switch {
	case maxUsage >= 97:
		return SeverityCritical
	case maxUsage >= 90:
		return SeverityWarning
	case maxUsage >= 80:
		return SeverityNotice
	default:
		return SeverityNormal
	}
}

func evaluateProcesses(stats ProcessStats) Severity {
	switch {
	case stats.Zombie >= 20 || stats.DiskSleep >= 20:
		return SeverityCritical
	case stats.Zombie >= 5 || stats.DiskSleep >= 10:
		return SeverityWarning
	case stats.Zombie > 0 || stats.DiskSleep >= 3:
		return SeverityNotice
	default:
		return SeverityNormal
	}
}

func evaluateNetwork(stats NetworkStats) Severity {
	var errors uint64
	var dropped uint64

	for _, iface := range stats.Interfaces {
		if iface.Name == "lo" {
			continue
		}

		errors += iface.RXErrors + iface.TXErrors
		dropped += iface.RXDropped + iface.TXDropped
	}

	switch {
	case errors >= 10000:
		return SeverityCritical
	case errors >= 1000 || dropped >= 10000:
		return SeverityWarning
	case errors > 0 || dropped >= 1000:
		return SeverityNotice
	default:
		return SeverityNormal
	}
}

func calculateOverall(snapshot Snapshot) Severity {
	overall := SeverityNormal

	update := func(value Severity) {
		if value > overall {
			overall = value
		}
	}

	update(snapshot.CPU.Severity)
	update(snapshot.Memory.Severity)
	update(snapshot.Processes.Severity)
	update(snapshot.Network.Severity)
	update(snapshot.SELinux.Severity)

	for _, fs := range snapshot.Filesystems {
		update(fs.Severity)
	}

	return overall
}

func saveBaseline(path string, snapshot Snapshot) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("cannot write baseline %s: %w", path, err)
	}

	return nil
}

func loadBaseline(path string) (Snapshot, error) {
	var snapshot Snapshot

	file, err := os.Open(path)
	if err != nil {
		return snapshot, fmt.Errorf("cannot open baseline %s: %w", path, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, 16*1024*1024))

	if err := decoder.Decode(&snapshot); err != nil {
		return snapshot, fmt.Errorf("cannot decode baseline %s: %w", path, err)
	}

	return snapshot, nil
}

func compareSnapshots(base Snapshot, current Snapshot) []Drift {
	var drift []Drift

	add := func(metric, baseline, now string, severity Severity) {
		drift = append(drift, Drift{
			Metric:   metric,
			Baseline: baseline,
			Current:  now,
			Severity: severity,
		})
	}

	compareFloat := func(metric string, baseValue, currentValue float64, notice, warning, critical float64) {
		if baseValue <= 0 {
			return
		}

		change := ((currentValue - baseValue) / baseValue) * 100
		absolute := change
		if absolute < 0 {
			absolute = -absolute
		}

		severity := SeverityNormal

		switch {
		case absolute >= critical:
			severity = SeverityCritical
		case absolute >= warning:
			severity = SeverityWarning
		case absolute >= notice:
			severity = SeverityNotice
		default:
			return
		}

		add(
			metric,
			fmt.Sprintf("%.2f", baseValue),
			fmt.Sprintf("%.2f", currentValue),
			severity,
		)
	}

	compareInt := func(metric string, baseValue, currentValue int, notice, warning, critical float64) {
		if baseValue <= 0 {
			if currentValue > 0 && baseValue == 0 {
				add(metric, strconv.Itoa(baseValue), strconv.Itoa(currentValue), SeverityNotice)
			}
			return
		}

		change := float64(currentValue-baseValue) / float64(baseValue) * 100
		absolute := change
		if absolute < 0 {
			absolute = -absolute
		}

		severity := SeverityNormal

		switch {
		case absolute >= critical:
			severity = SeverityCritical
		case absolute >= warning:
			severity = SeverityWarning
		case absolute >= notice:
			severity = SeverityNotice
		default:
			return
		}

		add(
			metric,
			strconv.Itoa(baseValue),
			strconv.Itoa(currentValue),
			severity,
		)
	}

	compareFloat("CPU load", base.CPU.Load1, current.CPU.Load1, 50, 150, 300)
	compareFloat("Memory usage", base.Memory.UsedPercent, current.Memory.UsedPercent, 15, 30, 50)

	compareInt("Process count", base.Processes.Total, current.Processes.Total, 20, 50, 100)
	compareInt("TCP IPv4 entries", base.Network.TCPIPv4, current.Network.TCPIPv4, 50, 150, 300)
	compareInt("TCP IPv6 entries", base.Network.TCPIPv6, current.Network.TCPIPv6, 50, 150, 300)
	compareInt("UDP IPv4 entries", base.Network.UDPIPv4, current.Network.UDPIPv4, 50, 150, 300)
	compareInt("UNIX sockets", base.Network.UnixSockets, current.Network.UnixSockets, 25, 75, 150)

	baseFS := make(map[string]FilesystemStats)
	for _, fs := range base.Filesystems {
		baseFS[fs.Path] = fs
	}

	for _, currentFS := range current.Filesystems {
		if old, ok := baseFS[currentFS.Path]; ok {
			difference := currentFS.UsedPercent - old.UsedPercent
			absolute := difference
			if absolute < 0 {
				absolute = -absolute
			}

			var severity Severity

			switch {
			case absolute >= 30:
				severity = SeverityCritical
			case absolute >= 15:
				severity = SeverityWarning
			case absolute >= 5:
				severity = SeverityNotice
			default:
				continue
			}

			add(
				"Filesystem "+currentFS.Path,
				fmt.Sprintf("%.1f%%", old.UsedPercent),
				fmt.Sprintf("%.1f%%", currentFS.UsedPercent),
				severity,
			)
		}
	}

	if base.SELinux.Mode != "" &&
		current.SELinux.Mode != "" &&
		base.SELinux.Mode != current.SELinux.Mode {
		add(
			"SELinux mode",
			base.SELinux.Mode,
			current.SELinux.Mode,
			SeverityWarning,
		)
	}

	sort.Slice(drift, func(i, j int) bool {
		if drift[i].Severity != drift[j].Severity {
			return drift[i].Severity > drift[j].Severity
		}
		return drift[i].Metric < drift[j].Metric
	})

	return drift
}

func printJSON(report Report) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
}

func printHuman(report Report) {
	s := report.Snapshot

	fmt.Println("Host Sentinel")
	fmt.Println("=============")
	fmt.Println()
	fmt.Printf("Host:         %s\n", s.Host.Hostname)
	fmt.Printf("Kernel:       %s\n", s.Host.Kernel)
	fmt.Printf("Architecture: %s\n", s.Host.Architecture)
	fmt.Printf("Uptime:       %s\n", formatDuration(s.Host.Uptime))
	fmt.Printf("Boot time:    %s\n", s.Host.BootTime)
	fmt.Printf("Generated:    %s\n", s.Timestamp)

	fmt.Println()
	fmt.Printf("%-12s %-10s %s\n", "Component", "State", "Summary")
	fmt.Printf("%-12s %-10s Load %.2f %.2f %.2f, %.2f per CPU\n",
		"CPU",
		s.CPU.Severity,
		s.CPU.Load1,
		s.CPU.Load5,
		s.CPU.Load15,
		s.CPU.LoadPerCPU,
	)

	fmt.Printf("%-12s %-10s %.1f%% used, %s available\n",
		"Memory",
		s.Memory.Severity,
		s.Memory.UsedPercent,
		formatBytes(s.Memory.AvailableBytes),
	)

	if s.Memory.SwapTotalBytes > 0 {
		fmt.Printf("%-12s %-10s %.1f%% used, %s total\n",
			"Swap",
			evaluateSwap(s.Memory),
			s.Memory.SwapUsedPercent,
			formatBytes(s.Memory.SwapTotalBytes),
		)
	} else {
		fmt.Printf("%-12s %-10s Not configured\n", "Swap", SeverityNormal)
	}

	fmt.Printf("%-12s %-10s %d total, %d zombie, %d disk sleep\n",
		"Processes",
		s.Processes.Severity,
		s.Processes.Total,
		s.Processes.Zombie,
		s.Processes.DiskSleep,
	)

	fmt.Printf("%-12s %-10s TCP %d/%d, UDP %d/%d, UNIX %d\n",
		"Network",
		s.Network.Severity,
		s.Network.TCPIPv4,
		s.Network.TCPIPv6,
		s.Network.UDPIPv4,
		s.Network.UDPIPv6,
		s.Network.UnixSockets,
	)

	fmt.Printf("%-12s %-10s %s\n",
		"SELinux",
		s.SELinux.Severity,
		s.SELinux.Mode,
	)

	fmt.Println()
	fmt.Println("Filesystems")
	fmt.Println("===========")

	if len(s.Filesystems) == 0 {
		fmt.Println("No configured filesystems were available")
	} else {
		for _, fs := range s.Filesystems {
			fmt.Printf("%-16s %-10s %6.1f%% used  %6.1f%% inodes  %s free\n",
				fs.Path,
				fs.Severity,
				fs.UsedPercent,
				fs.InodePercent,
				formatBytes(fs.FreeBytes),
			)
		}
	}

	fmt.Println()
	fmt.Println("Pressure")
	fmt.Println("========")
	fmt.Printf("CPU some avg10:     %.2f%%\n", s.CPU.PressureSome10)
	fmt.Printf("CPU full avg10:     %.2f%%\n", s.CPU.PressureFull10)
	fmt.Printf("Memory some avg10:  %.2f%%\n", s.Memory.PressureSome10)
	fmt.Printf("Memory full avg10:  %.2f%%\n", s.Memory.PressureFull10)

	fmt.Println()
	fmt.Println("Network Interfaces")
	fmt.Println("==================")

	for _, iface := range s.Network.Interfaces {
		fmt.Printf("%-12s %-10s RX %10s  TX %10s  errors %d/%d  drops %d/%d\n",
			iface.Name,
			iface.State,
			formatBytes(iface.RXBytes),
			formatBytes(iface.TXBytes),
			iface.RXErrors,
			iface.TXErrors,
			iface.RXDropped,
			iface.TXDropped,
		)
	}

	fmt.Println()
	fmt.Println("Socket State")
	fmt.Println("============")
	fmt.Printf("Sockets used:   %d\n", s.Network.SocketUsed)
	fmt.Printf("TCP in use:     %d\n", s.Network.TCPInUse)
	fmt.Printf("TCP TIME_WAIT:  %d\n", s.Network.TCPTimeWait)
	fmt.Printf("TCP allocated:  %d\n", s.Network.TCPAllocated)
	fmt.Printf("UDP in use:     %d\n", s.Network.UDPInUse)

	if len(report.Drift) > 0 {
		fmt.Println()
		fmt.Println("Baseline Drift")
		fmt.Println("==============")

		for _, item := range report.Drift {
			fmt.Printf("%-10s %-24s %s -> %s\n",
				item.Severity,
				item.Metric,
				item.Baseline,
				item.Current,
			)
		}
	} else if len(report.Drift) == 0 && report.Snapshot.Overall >= SeverityNormal {
	}

	fmt.Println()
	fmt.Printf("Overall: %s\n", s.Overall)
}

func evaluateSwap(memory MemoryStats) Severity {
	switch {
	case memory.SwapUsedPercent >= 90:
		return SeverityCritical
	case memory.SwapUsedPercent >= 75:
		return SeverityWarning
	case memory.SwapUsedPercent >= 40:
		return SeverityNotice
	default:
		return SeverityNormal
	}
}

func formatBytes(value uint64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
		tib = 1024 * gib
	)

	switch {
	case value >= tib:
		return fmt.Sprintf("%.2f TiB", float64(value)/float64(tib))
	case value >= gib:
		return fmt.Sprintf("%.2f GiB", float64(value)/float64(gib))
	case value >= mib:
		return fmt.Sprintf("%.2f MiB", float64(value)/float64(mib))
	case value >= kib:
		return fmt.Sprintf("%.2f KiB", float64(value)/float64(kib))
	default:
		return fmt.Sprintf("%d B", value)
	}
}

func formatDuration(seconds uint64) string {
	days := seconds / 86400
	seconds %= 86400
	hours := seconds / 3600
	seconds %= 3600
	minutes := seconds / 60
	seconds %= 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}

	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}

	return fmt.Sprintf("%ds", seconds)
}
