// Command cbsd-web is a web interface for CBSD (jails, bhyve and Xen on FreeBSD).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/cbsd-web/cbsd-web/internal/audit"
	"github.com/cbsd-web/cbsd-web/internal/auth"
	"github.com/cbsd-web/cbsd-web/internal/config"
	"github.com/cbsd-web/cbsd-web/internal/hoststat"
	"github.com/cbsd-web/cbsd-web/internal/server"
)

var version = "0.2.1"

const defaultConfig = "/usr/local/etc/cbsd-web/cbsd-web.conf"

func usage() {
	fmt.Fprintf(os.Stderr, `cbsd-web %s — веб-интерфейс для CBSD

Использование:
  cbsd-web [-config FILE] serve                  запустить сервер
  cbsd-web [-config FILE] useradd NAME [-role R] [-generate]
                                                 создать/изменить пользователя (роль: admin|operator|viewer)
  cbsd-web [-config FILE] userdel NAME           удалить пользователя
  cbsd-web [-config FILE] users                  список пользователей
  cbsd-web [-config FILE] check                  проверить конфигурацию
  cbsd-web version
`, version)
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	fs := flag.NewFlagSet("cbsd-web", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig, "config file")
	allowRoot := fs.Bool("allow-root", false, "allow running the server as root (not recommended)")
	fs.Usage = usage
	fs.Parse(os.Args[1:])
	args := fs.Args()
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if cmd == "version" {
		fmt.Println(version)
		return
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	switch cmd {
	case "serve":
		if os.Geteuid() == 0 && !*allowRoot {
			log.Fatal("refusing to run as root: run as the unprivileged 'cbsdweb' user (see deploy/), or pass -allow-root")
		}
		err = serve(cfg)
	case "useradd", "passwd":
		err = userAdd(cfg, args)
	case "userdel":
		err = userDel(cfg, args)
	case "users":
		err = listUsers(cfg)
	case "check":
		fmt.Printf("config OK\nlisten: %s (tls: %v)\nworkdir: %s\ncbsd: %s\n", cfg.Listen, cfg.TLSEnabled(), cfg.Workdir, strings.Join(cfg.CBSDCommand, " "))
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serve(cfg *config.Config) error {
	// Development only (make dev): stand-ins for ifconfig, netstat, ps and zfs.
	if d := os.Getenv("CBSDWEB_DEV_TOOLS"); d != "" {
		hoststat.UseToolsDir(d)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	users, err := auth.OpenStore(cfg.UsersFile)
	if err != nil {
		return err
	}
	if users.Count() == 0 {
		log.Printf("WARNING: no users defined; create one with: cbsd-web useradd admin -role admin")
	}
	al, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return err
	}
	defer al.Close()
	srv, err := server.New(cfg, users, al, version)
	if err != nil {
		return err
	}
	defer srv.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	al.Log(audit.Entry{Event: "server.start", Detail: map[string]string{"version": version, "listen": cfg.Listen}})
	return srv.ListenAndServe(ctx)
}

func userAdd(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("useradd", flag.ExitOnError)
	role := fs.String("role", "admin", "admin|operator|viewer")
	gen := fs.Bool("generate", false, "generate a random password and print it")
	if len(args) == 0 {
		return errors.New("usage: cbsd-web useradd NAME [-role R] [-generate]")
	}
	name := args[0]
	fs.Parse(args[1:])
	store, err := auth.OpenStore(cfg.UsersFile)
	if err != nil {
		return err
	}
	var pw string
	if *gen {
		b := make([]byte, 18)
		rand.Read(b)
		pw = base64.RawURLEncoding.EncodeToString(b)
	} else {
		pw, err = readPassword()
		if err != nil {
			return err
		}
	}
	if err := store.Set(name, pw, auth.Role(*role)); err != nil {
		return err
	}
	if *gen {
		fmt.Printf("user %s (%s) password: %s\n", name, *role, pw)
	} else {
		fmt.Printf("user %s (%s) saved\n", name, *role)
	}
	return nil
}

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "Пароль: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Повторите: ")
	p2, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", errors.New("пароли не совпадают")
	}
	return string(p1), nil
}

func userDel(cfg *config.Config, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: cbsd-web userdel NAME")
	}
	store, err := auth.OpenStore(cfg.UsersFile)
	if err != nil {
		return err
	}
	return store.Delete(args[0])
}

func listUsers(cfg *config.Config) error {
	store, err := auth.OpenStore(cfg.UsersFile)
	if err != nil {
		return err
	}
	for _, u := range store.List() {
		fmt.Printf("%-24s %s\n", u.Name, u.Role)
	}
	return nil
}
