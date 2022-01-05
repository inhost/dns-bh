package main

import (
	"crypto/sha256"
	"database/sql"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"

	"path/filepath"

	"github.com/epix-dev/dns-bh/lib"

	_ "github.com/lib/pq"
)

const hazardFile = "hazard_domains.txt"
const malwareFile = "malware_domains.txt"

type ByLength []string

func (s ByLength) Len() int {
	return len(s)
}
func (s ByLength) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ByLength) Less(i, j int) bool {
	return len(s[i]) < len(s[j])
}

type domains struct {
	hazard  []string
	malware []string
}

func (d *domains) load(db *sql.DB) error {
	var domain string
	var selectSQL string

	selectSQL = `SELECT domain FROM hazard
				WHERE deleted_at IS NULL AND domain NOT IN (SELECT domain FROM whitelist WHERE deleted_at IS NULL) ORDER BY 1`

	if rows, err := db.Query(selectSQL); err == nil {
		for rows.Next() {
			if err = rows.Scan(&domain); err == nil {
				d.hazard = append(d.hazard, domain)
			}
		}
		rows.Close()
	} else {
		return err
	}

	// selectSQL = `SELECT domain FROM malware
	// 			WHERE deleted_at IS NULL AND domain NOT IN (SELECT domain FROM whitelist WHERE deleted_at IS NULL) ORDER BY 1`
	//
	// if rows, err := db.Query(selectSQL); err == nil {
	// 	for rows.Next() {
	// 		if err = rows.Scan(&domain); err == nil {
	// 			d.malware = append(d.malware, domain)
	// 		}
	// 	}
	// 	rows.Close()
	// } else {
	// 	return err
	// }

	return nil
}

func (d *domains) save(outputDir string) error {
	return nil
}

func fileSHA256(filePath string) (string, error) {
	var SHA256String string

	file, err := os.Open(filePath)
	if err != nil {
		return SHA256String, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return SHA256String, err
	}

	SHA256String = hex.EncodeToString(hash.Sum(nil))

	return SHA256String, nil
}

func fileSave(filePath string, d []string) (bool, error) {
	var err error
	var changed bool = false
	var sha256Before string = ""
	var sha256After string

	log.Printf("Save domains to file: %s", filePath)

	if _, err = os.Stat(filePath); !os.IsNotExist(err) {
		log.Print("Compute file hash before export")
		if sha256Before, err = fileSHA256(filePath); err != nil {
			return changed, err
		}
		log.Printf(" - %s", sha256Before)
	} else {
		log.Print("File doesn't exist")
	}

  fileDir := filepath.Dir(filePath)
	log.Printf("Create temporary file in: %s", fileDir)

	tmpfile, err := ioutil.TempFile(fileDir, "dns-bh_")
	if err != nil {
		return changed, err
	}
	defer os.Remove(tmpfile.Name()) // clean up
	log.Printf("Temporary file path: %s", tmpfile.Name())

	sort.Sort(ByLength(d))

	log.Print("Write domains to file")
	for _, domain := range d {
		if _, err := tmpfile.WriteString(domain + "\n"); err != nil {
			return changed, err
		}
	}

	tmpfile.Chmod(0444)

	if err = tmpfile.Close(); err != nil {
		return changed, err
	}

	log.Print("Compute new file hash")
	if sha256After, err = fileSHA256(tmpfile.Name()); err != nil {
		return changed, err
	}
	log.Printf(" - %s", sha256After)

	if sha256Before != sha256After {
		// var file *os.File
		//
		// if file, err = os.Create(filepath.Join(filepath.Dir(filePath), "dns-bh.reload")); err != nil {
		// 	return err
		// }
		// defer file.Close()
		//
		// file.Chmod(0644)

		log.Print("Files differ, has changes")

		changed = true
	}

	log.Printf("Rename temporary file to: %s", filePath)
	if err = os.Rename(tmpfile.Name(), filePath); err != nil {
		return changed, err
	}

	log.Print("All done.")

	return changed, nil
}

func main() {
	var err error
	var db *sql.DB
	var dom domains
	var changed bool

	log.Print("Configure updater")

	var cfgDir string
	var outputDir string
	var cfg lib.Config

	flag.StringVar(&cfgDir, "cfg-dir", "/opt/dns-bh/etc", "Config dir path")
	flag.StringVar(&outputDir, "output-dir", "/etc/powerdns", "Output dir path")
	flag.Parse()

	lib.ConfigInit(cfgDir)
	if !lib.ConfigLoad(&cfg) {
		log.Fatalf("Error loading config")
	}

	db, err = lib.ConnectDb(cfg.DB.Host, cfg.DB.Port, cfg.DB.User, cfg.DB.Password, cfg.DB.Name)
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()

	log.Print("Loading domains from database")

	if err = dom.load(db); err != nil {
		log.Fatalln(err)
	}

	hazardPath := filepath.Join(outputDir, hazardFile)
	if changed, err = fileSave(hazardPath, dom.hazard); err != nil {
		log.Fatalln(err)
	}

	if changed == true {
		// Export new file to every managed host
		var report bytes.Buffer
		nodesFile := "nodes.txt"
		nodesPath := filepath.Join(outputDir, nodesFile)

		log.Print("Reading nodes from file: ", nodesPath)

		content, err := ioutil.ReadFile(nodesPath)
		if err != nil {
		    log.Fatalln(err)
		}
		hosts := strings.Split(string(content), "\n")
		log.Print(hosts)

		for lno, hostSetting := range hosts {
			if len(strings.TrimSpace(hostSetting)) > 0 {
				settings := strings.Split(hostSetting, " ")
				if len(settings) == 2 {
					host := settings[0]
					keyFile := settings[1]
					log.Printf(" - process %s using key %s", host, keyFile)

					report.WriteString(fmt.Sprintf(" - %s\n", host))

					keyPath := filepath.Join(outputDir, keyFile)

					if _, err := os.Stat(keyPath); os.IsNotExist(err) {
						log.Printf("  ! missing keyfile, skip host")

						report.WriteString("    keyfile is missing, not updated")
					} else {
						target := fmt.Sprintf("root@%s:/etc/pdns", host)
						cmd := exec.Command("scp", "-B", "-v", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=" + keyPath, hazardPath, target)

						log.Printf("   executing: %s\n", strings.Join(cmd.Args, " "))

						output, err := cmd.CombinedOutput()
						if err != nil {
							report.WriteString(fmt.Sprintf("    ERROR: %s\n\n", err))
						}
						lines := strings.Split(string(output), "\n")
						for _, line := range lines {
							log.Printf("      | %s\n", line)
							report.WriteString(fmt.Sprintf("   | %s\n", line))
						}
						report.WriteString("   +---\n")
					}
				} else {
					log.Printf("Invalid input line found @%d", lno)
				}
			}
		}

		lib.ReportExport(&cfg, "Blackhole file export", report.String())
	}

	log.Printf("Saved hazard domains: %d", len(dom.hazard))

	// if err = fileSave(filepath.Join(outputDir, malwareFile), dom.malware); err != nil {
	// 	log.Fatalln(err)
	// }
	//
	// log.Printf("saved malware domains: %d", len(dom.malware))
}
