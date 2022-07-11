package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/gopasspw/gopass/pkg/gopass/api"
)

type BitWardenExport struct {
	Encrypted bool              `json:"encrypted,omitempty"`
	Folders   []BitWardenFolder `json:"folders,omitempty"`
	Items     []BitwardenItem   `json:"items,omitempty"`
}

type BitWardenFolder struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type BitwardenItem struct {
	OrganizationID string         `json:"organizationId"`
	CollectionIds  []string       `json:"collectionIds,omitempty"`
	FolderID       string         `json:"folderId,omitempty"`
	Type           int            `json:"type,omitempty"`
	Name           string         `json:"name,omitempty"`
	Notes          string         `json:"notes,omitempty"`
	Favorite       bool           `json:"favorite,omitempty"`
	Fields         []string       `json:"fields,omitempty"`
	Login          BitwardenLogin `json:"login,omitempty"`
	SecureNote     string         `json:"secureNote,omitempty"`
	Card           string         `json:"card,omitempty"`
	Identity       string         `json:"identity,omitempty"`
	Reprompt       int            `json:"reprompt,omitempty"`
}

type BitwardenLogin struct {
	Uris     []BitwardenURI `json:"uris,omitempty"`
	Username string         `json:"username,omitempty"`
	Password string         `json:"password,omitempty"`
	Totp     string         `json:"totp,omitempty"`
}

type BitwardenURI struct {
	Match int    `json:"match,omitempty"`
	URI   string `json:"uri,omitempty"`
}

var m = make(map[string]bool)
var a = []string{}

func main() {
	ctx := context.Background()

	// trap Ctrl+C and call cancel on the context.
	ctx, cancel := context.WithCancel(ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	defer func() {
		signal.Stop(sigChan)
		cancel()
	}()
	go func() {
		select {
		case <-sigChan:
			cancel()
		case <-ctx.Done():
		}
	}()

	gp, err := api.New(ctx)
	check("api.New", err)

	var export BitWardenExport

	secretNames, err := gp.List(ctx)
	check("gp.List", err)

	for _, secretName := range secretNames {

		secret, err := gp.Get(ctx, secretName, "")
		if err != nil { // retry 10
			for i := 0; i < 10; i++ {
				os.Stderr.WriteString(fmt.Sprintf("[%s][gp.Get]", secretName))
				secret, err = gp.Get(ctx, secretName, "")
				if err == nil {
					break
				}
			}
		}
		check("gp.Get", err)

		baseName := filepath.Base(secretName)
		folderName := filepath.Dir(secretName)

		item := BitwardenItem{
			Type:  1,
			Name:  baseName,
			Notes: secret.Body(),
			Login: BitwardenLogin{
				Password: secret.Password(),
			},
		}

		if folderName != "." {
			item.FolderID = md5sum(folderName)
			add(folderName)
		}

		for _, key := range secret.Keys() {
			if key == "login" || key == "username" || key == "email" {
				item.Login.Username, _ = secret.Get(key)
				continue
			}

			// get URL
			if key == "url" {
				uri, _ := secret.Get(key)
				item.Login.Uris = append(item.Login.Uris, BitwardenURI{
					Match: 0,
					URI:   uri,
				})
				continue
			}

			// Get MFA codeas
			if key == "totp" || key == "2fa" || key == "mfa" {
				item.Login.Totp, _ = secret.Get(key)
				continue
			}

			// append other keys as notes
			note, _ := secret.Get(key)
			item.Notes = fmt.Sprintf("%s\n%s: %s", item.Notes, key, note)
		}

		export.Items = append(export.Items, item)
	}

	for folderName := range m {
		export.Folders = append(export.Folders, BitWardenFolder{
			ID:   md5sum(folderName),
			Name: folderName,
		})
	}

	b, err := json.Marshal(export)
	check("json.Marshal", err)
	os.Stdout.Write(b)
}

func add(s string) {
	if m[s] {
		return // Already in the map
	}
	a = append(a, s)
	m[s] = true
}

func md5sum(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func check(s string, err error) {
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("[%s] %v\n", s, err))
		os.Exit(1)
	}
}
