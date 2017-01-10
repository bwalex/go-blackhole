package main

import (
	"strings"
	"flag"
	"fmt"
	"regexp"
	"time"
	"net"
	"log"
	"syscall"
	"database/sql"
	"github.com/coreos/go-systemd/sdjournal"
	_ "github.com/mattn/go-sqlite3"
	"github.com/vishvananda/netlink"
)

const journalPathDefault = "/var/log/journal"
const dbPathDefault = "/var/lib/blackhole.db"
const ipv4PrefixDefault = 32
const ipv6PrefixDefault = 64
const blacklistDurationDefault = time.Duration(30)*time.Minute
const sshdSyslogIdentifier = "sshd"

var globalState = struct {
	journalChan        chan string
	exprs              []*regexp.Regexp
	db                 *sql.DB
	ipv4PrefixLen      int
	ipv6PrefixLen      int
	blacklistDuration  time.Duration
}{
	journalChan:       make(chan string, 10),
	exprs:             []*regexp.Regexp{
		regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?[^\s]+ from ([^\s]+) port`),
		// regexp.MustCompile(`Invalid user [^\s]+ from ([^\s]+)`),
	},
	db:                nil,
	ipv4PrefixLen:     ipv4PrefixDefault,
	ipv6PrefixLen:     ipv6PrefixDefault,
	blacklistDuration:  blacklistDurationDefault,
}

type JournalChanWriter struct {
}

func (jcw JournalChanWriter) Write(b []byte) (int, error) {
	globalState.journalChan <- (strings.TrimSpace(string(b)))
	return len(b), nil
}

func ipToMask(ip net.IP) *net.IPNet {
	var ipMask net.IPMask
	if ip.To4() != nil {
		ipMask = net.CIDRMask(globalState.ipv4PrefixLen, 32)
	} else {
		ipMask = net.CIDRMask(globalState.ipv6PrefixLen, 128)
	}

	return &net.IPNet{
		IP:   ip,
		Mask: ipMask,
	}
}

func addBlackholeRoute(ip net.IP) error {
	ipnet := ipToMask(ip)
	log.Printf("INFO: Adding blackhole route for %s", ipnet.String())

	err := netlink.RouteAdd(&netlink.Route{
		Dst:  ipnet,
		Type: syscall.RTN_BLACKHOLE,
	})

	return err
}

func removeBlackholeRoute(ip net.IP) error {
	ipnet := ipToMask(ip)
	log.Printf("INFO: Removing blackhole route for %s", ipnet.String())

	err := netlink.RouteDel(&netlink.Route{
		Dst:  ipnet,
		Type: syscall.RTN_BLACKHOLE,
	})

	return err
}

func processLogEntry(logEntry string) {
	ip := ""
	for _,expr := range globalState.exprs {
		matches := expr.FindStringSubmatch(logEntry)
		if matches != nil {
			ip = matches[1]
			break
		}
	}

	if ip == "" {
		return
	}

	expiry_ts := time.Now().Unix() + int64(globalState.blacklistDuration.Seconds())
	log.Printf("INFO: Recording ban for ip=%s", ip)

	// Record in database
	_, err := globalState.db.Exec(fmt.Sprintf("REPLACE INTO bans(ip, expiry_ts) VALUES('%s', %d)", ip, expiry_ts))

	if err != nil {
		log.Printf("ERR:  db(insert): %s", err)
		return
	}

	// Apply blacklist route
	err = addBlackholeRoute(net.ParseIP(ip))
	if err != nil {
		log.Printf("ERR:  route(add): %s", err)
		return
	}
}

func processTick() {
	// Iterate through bans table and expire old entries (as well as removing associated routes)
	rows, err := globalState.db.Query(fmt.Sprintf("SELECT ip FROM bans WHERE expiry_ts < %d", time.Now().Unix()))
	if err != nil {
		log.Fatal("db(select): %s", err)
	}

	var ips []string

	defer rows.Close()
	for rows.Next() {
		var ip string

		if err = rows.Scan(&ip); err != nil {
			log.Printf("ERR:  db(scan): %s", err)
			continue
		}

		ips = append(ips, ip)
	}

	err = rows.Err()
	if err != nil {
		log.Fatal("db(rows): %s", err)
	}

	for _,ip := range ips {
		log.Printf("INFO: Expiring ban for ip=%s", ip)

		err = removeBlackholeRoute(net.ParseIP(ip))
		if err != nil {
			log.Printf("ERR:  route(del): %s", err)
			continue
		}

		_, err = globalState.db.Exec(fmt.Sprintf("DELETE FROM bans WHERE ip = '%s'", ip))
		if err != nil {
			log.Printf("ERR:  db(delete): %s", err)
		}
	}
}

func eventLoop() {
	ticker := time.NewTicker(time.Second * 10)
	for {
		select {
		case logEntry := <-globalState.journalChan:
			processLogEntry(logEntry)
		case <-ticker.C:
			processTick()
		}
	}
}

func main() {
	journalPathPtr := flag.String("journal-path", journalPathDefault, "systemd journal path")
	dbPathPtr := flag.String("db", dbPathDefault, "database file location")

	ipv4PrefixPtr := flag.Int("ipv4-prefix", ipv4PrefixDefault, "IPv4 prefix length to blacklist")
	ipv6PrefixPtr := flag.Int("ipv6-prefix", ipv6PrefixDefault, "IPv6 prefix length to blacklist")
	blacklistDurationPtr := flag.Duration("blacklist-duration", blacklistDurationDefault, "blacklist duration")

	flag.Parse()

	globalState.ipv4PrefixLen = *ipv4PrefixPtr
	globalState.ipv6PrefixLen = *ipv6PrefixPtr
	globalState.blacklistDuration = *blacklistDurationPtr

	jr, err := sdjournal.NewJournalReader(sdjournal.JournalReaderConfig{
		Path: *journalPathPtr,
		NumFromTail: 1,
		Matches: []sdjournal.Match{
			{
				Field: sdjournal.SD_JOURNAL_FIELD_SYSLOG_IDENTIFIER,
				Value: sshdSyslogIdentifier,
			},
		},
	})
	if err != nil {
		log.Fatal("journal: %s", err)
	}
	defer jr.Close()

	globalState.db, err = sql.Open("sqlite3", *dbPathPtr)
	if err != nil {
		log.Fatal("db(open): %s", err)
	}

	defer globalState.db.Close()

	_, err = globalState.db.Exec(`
	    CREATE TABLE IF NOT EXISTS bans (ip TEXT NOT NULL UNIQUE, expiry_ts INTEGER);
	`)
	if err != nil {
		log.Fatal("db(create): %s", err)
	}

	go eventLoop()

	jr.Follow(nil, JournalChanWriter{})
}
