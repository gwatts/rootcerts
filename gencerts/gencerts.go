// Copyright 2015 Gareth Watts
// Licensed under an MIT license
// See the LICENSE file for details

/*
Command gencerts converts root CA certificates from the Mozilla NSS project to a .go file.

The program parses a certdata.txt file and extracts only those certificates that have been
labeled as trusted for use as a certificate authority.  Other certificates in the certdata.txt
file are ignored.

Without arguments, gencert reads a certdata.txt file from stdin and emits a .go file
to stdout that contains the parsed certificates along with some helper methods to access them.

The program can also download the latest certdata.txt file from the Mozilla NSS Mercurial site
(or another url using the -url option) or read and write to a specified filename using -source
and -target.

NOTE: Using -download with an https url requires that the program have access to root certificates!
The certdata format used by the NSS project is also subject to intermittant change and may cause
this program to fail.
*/
package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/gwatts/rootcerts/certparse"
)

const (
	defaultDownloadURL = "https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt"
)

var (
	packageName = flag.String("package", "main", "Name of the package to use for generated file")
	download    = flag.Bool("download", false, "Set to true to download the latest certificate data from Mozilla. See -url")
	downloadURL = flag.String("url", defaultDownloadURL, "URL to download certificate data from if -download is true")
	sourceFile  = flag.String("source", "", "Source filename to read certificate data from if -download is false.  Defaults to stdin")
	outputFile  = flag.String("target", "", "Filename to write .go output file to.  Defaults to stdout")
)

const (
	indent     = 3
	indentWrap = 64
)

var tplText = `{{define "main"}}package {{.package}}

// Generated using github.com/gwatts/rootcerts/gencert
// Generated on {{ .time }}
// Input file SHA1: {{ .filesha1 }}

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// TrustLevel defines for which purposes the certificate is trusted to issue
// certificates (ie. to act as a CA)
type TrustLevel int

const (
	ServerTrustedDelegator TrustLevel = 1 << iota // Trusted for issuing server certificates
	EmailTrustedDelegator                         // Trusted for issuing email certificates
	CodeTrustedDelegator                          // Trusted for issuing code signing certificates
)

// A Cert defines a single unparsed certificate.
type Cert struct {
	Label  string
	Serial string
	Trust  TrustLevel
	DER    []byte
}

// X509Cert parses the certificate into a *x509.Certificate.
func (c *Cert) X509Cert() *x509.Certificate {
	cert, err := x509.ParseCertificate(c.DER)
	if err != nil {
		panic(fmt.Sprintf("unexpected failure parsing certificate %q/%s: %s", c.Label, c.Serial, err))
	}
	return cert
}

var serverCertPool *x509.CertPool
var serverOnce sync.Once

// ServerCertPool returns a pool containing all root CA certificates that are trusted
// for issuing server certificates.
func ServerCertPool() *x509.CertPool {
	serverOnce.Do(func() {
		serverCertPool = x509.NewCertPool()
		for _, c := range CertsByTrust(ServerTrustedDelegator) {
			serverCertPool.AddCert(c.X509Cert())
		}
	})
	return serverCertPool
}

// CertsByTrust returns only those certificates that match all bits of
// the specified TrustLevel.
func CertsByTrust(t TrustLevel) (result []Cert) {
	for _, c := range certs {
		if c.Trust&t == t {
			result = append(result, c)
		}
	}
	return result
}

// UpdateDefaultTransport updates the configuration for http.DefaultTransport
// to use the root CA certificates defined here when used as an HTTP client.
//
// It will return an error if the DefaultTransport is not actually an *http.Transport.
func UpdateDefaultTransport() error {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{RootCAs: ServerCertPool()}
		} else {
			t.TLSClientConfig.RootCAs = ServerCertPool()
		}
	} else {
		return errors.New("http.DefaultTransport is not an *http.Transport")
	}
	return nil
}

// Certs returns all trusted certificates extracted from certdata.txt.
func Certs() []Cert {
	return certs
}

// make this unexported to avoid generating a huge documentation page.
var certs = []Cert{
{{- range .certs }}
	{
		Label:  "{{ .Label }}",
		Serial: "{{ .Cert.SerialNumber }}",
		Trust:  {{ .Trust }},
		DER: {{ .Cert.Raw | indentbytes }},
	},
{{- end }}
}
{{end}}
`
var funcMap = template.FuncMap{
	"indentbytes": indentBytes,
}

var tpl = template.Must(template.New("data").Funcs(funcMap).Parse(tplText))

func fail(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(100)
}

func indentBytes(data []byte) string {
	var out []byte
	idt := strings.Repeat("\t", indent)

	s := fmt.Sprintf("%#v", data)
	for line := 0; len(s) > indentWrap; line++ {
		if sp := strings.IndexByte(s[indentWrap:], ','); sp > -1 {
			if line > 0 {
				out = append(out, idt...)
			}
			out = append(out, strings.TrimSpace(s[:indentWrap+sp+1])...)
			out = append(out, '\n')
			s = s[indentWrap+sp+1:]
		} else {
			break
		}
	}
	out = append(out, idt...)
	out = append(out, strings.TrimSpace(s)...)
	return string(out)
}

type hashReader struct {
	hash.Hash
	r io.Reader
}

func (hr *hashReader) Read(p []byte) (n int, err error) {
	n, err = hr.r.Read(p)
	if n > 0 {
		hr.Hash.Write(p[0:n])
	}
	return n, err
}

func newHashReader(r io.Reader, h hash.Hash) *hashReader {
	return &hashReader{h, r}
}

func main() {
	flag.Parse()

	var (
		source io.Reader
		target io.Writer
		err    error
	)

	if *download {
		resp, err := http.Get(*downloadURL)
		if err != nil {
			fail("Failed to download source: %s", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			fail("Non-200 status code when downloading source: %s", resp.Status)
		}
		source = resp.Body

	} else if *sourceFile == "" || *sourceFile == "-" {
		source = os.Stdin

	} else {
		source, err = os.Open(*sourceFile)
		if err != nil {
			fail("Failed to open source file: %s", err)
		}
	}

	if *outputFile == "" || *outputFile == "-" {
		target = os.Stdout

	} else {
		target, err = os.Create(*outputFile)
		if err != nil {
			fail("Failed to open target file: %s", err)
		}
	}

	hashSource := newHashReader(source, sha1.New())

	certs, err := certparse.ReadTrustedCerts(hashSource)
	if err != nil {
		fail("Failed to read certificates: %s", err)
	}

	tplParams := map[string]interface{}{
		"package":  *packageName,
		"certs":    certs,
		"time":     time.Now().Format(time.RFC1123Z),
		"filesha1": fmt.Sprintf("%0x", hashSource.Sum(nil)),
	}

	if err = tpl.ExecuteTemplate(target, "main", tplParams); err != nil {
		fail("Template execution failed: %s", err)
	}
}
