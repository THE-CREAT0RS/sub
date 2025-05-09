package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/miekg/dns"
)

func fetchDnsRecords(domain, server string) (map[string]interface{}, error) {
	qname := dns.Fqdn(domain)
	client := new(dns.Client)

	// dns record types, avoid ANY type fetches
	recordTypes := []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT,
		dns.TypeNS, dns.TypeSOA, dns.TypeSRV, dns.TypePTR,
		dns.TypeCAA, dns.TypeNAPTR, dns.TypeCNAME,
	}

	results := make(map[string]interface{})
	for _, t := range recordTypes {
		msg := new(dns.Msg)
		msg.SetQuestion(qname, t)
		msg.RecursionDesired = true

		r, _, err := client.Exchange(msg, server)
		if err != nil {
			// capture error for record type
			results[dns.Type(t).String()] = map[string]string{"error": err.Error()}
			continue
		}
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
			continue
		}

		// collect all RR strings for this type
		values := make([]string, 0, len(r.Answer))
		for _, rr := range r.Answer {
			values = append(values, rr.String())
		}
		results[dns.Type(t).String()] = values
	}
	return results, nil
}

func main() {
	domain := flag.String("domain", "", "Domain name to query (required)")
	server := flag.String("server", "", "DNS server address (host:port). Leave empty to use system default resolver")
	flag.Parse()
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "Error: --domain flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// determine which DNS server to use as a resolver
	var serverAddr string
	if *server == "" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(conf.Servers) == 0 {
			fmt.Fprintln(os.Stderr, "Error: could not load system DNS configuration")
			os.Exit(1)
		}
		serverAddr = fmt.Sprintf("%s:%s", conf.Servers[0], conf.Port)
	} else {
		serverAddr = *server
	}

	// fetch dns records
	recMap, err := fetchDnsRecords(*domain, serverAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching DNS records: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(recMap, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
