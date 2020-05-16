package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

func main() {

	var (
		privKey, pubKeyPath             string
		quotePath, pcrReadPath, sigPath string
		sigOutPath, quoteOutPath        string
	)

	log.SetOutput(os.Stdout)

	debug := flag.Bool("debug", false, "Enable debug logging")

	validateKeypairCmd := flag.NewFlagSet("validateKeypair", flag.ExitOnError)
	validateKeypairCmd.StringVar(&privKey, "privKey", "", "decimal representation of the private key")
	validateKeypairCmd.StringVar(&pubKeyPath, "pubKeyPath", "", "path of the public key file in pem format")

	validateQuoteCmd := flag.NewFlagSet("validateQuote", flag.ExitOnError)
	validateQuoteCmd.StringVar(&quotePath, "quotePath", "", "path of the quote")
	validateQuoteCmd.StringVar(&sigPath, "sigPath", "", "path of the signature")
	validateQuoteCmd.StringVar(&pcrReadPath, "pcrReadPath", "", "path of a file containing PCR readings")
	validateQuoteCmd.StringVar(&pubKeyPath, "pubKeyPath", "", "path of the public key file in pem format")
	validateQuoteCmd.StringVar(&privKey, "privKey", "", "decimal representation of the private key")

	forgeQuoteCmd := flag.NewFlagSet("forgeQuote", flag.ExitOnError)
	forgeQuoteCmd.StringVar(&quotePath, "quotePath", "", "path of the quote")
	forgeQuoteCmd.StringVar(&quoteOutPath, "quoteOutPath", "", "path of the output quote")
	forgeQuoteCmd.StringVar(&pcrReadPath, "pcrReadPath", "", "path of a file containing PCR readings")
	forgeQuoteCmd.StringVar(&privKey, "privKey", "", "decimal representation of the private key")
	forgeQuoteCmd.StringVar(&pubKeyPath, "pubKeyPath", "", "path of the public key file in pem format")
	forgeQuoteCmd.StringVar(&sigOutPath, "sigOutPath", "", "path of the signature generated on the quote")

	flagSets := []*flag.FlagSet{validateKeypairCmd, validateQuoteCmd, forgeQuoteCmd}

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\n=== Supported commands ===\n")
		for _, c := range flagSets {
			fmt.Fprintf(flag.CommandLine.Output(), "-> Command %s:\n", c.Name())
			c.PrintDefaults()
		}
	}

	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatalf("command required")
		flag.Usage()
		os.Exit(1)
	}
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	flagSetArgs := os.Args[flag.NFlag()+2:]

	switch os.Args[flag.NFlag()+1] {

	case "validateKeypair":
		validateKeypairCmd.Parse(flagSetArgs)
		kv, err := validateKeypair(privKey, pubKeyPath)
		if err != nil {
			log.Fatalf(err.Error())
		}
		m, err := json.MarshalIndent(kv, " ", " ")
		if err != nil {
			log.Fatalf(fmt.Sprintf("could not marshal result: %v", err))
		}
		fmt.Println(string(m))
	case "validateQuote":
		validateQuoteCmd.Parse(flagSetArgs)
		if len(quotePath) == 0 {
			log.Fatalf("quote path undefined")
		}
		if len(pubKeyPath) == 0 {
			log.Fatalf("pubKeyPath undefined")
		}
		if len(privKey) == 0 {
			log.Fatalf("privKey undefined")
		}

		q, err := readQuote(quotePath)
		if err != nil {
			log.Fatalf(err.Error())
		}
		m, err := json.MarshalIndent(q, " ", " ")
		if err != nil {
			log.Fatalf(fmt.Sprintf("could not marshal result: %v", err))
		}
		fmt.Println(string(m))
		valid, err := validateQuote(q, sigPath, privKey, pubKeyPath)
		if err != nil {
			log.Fatalf(fmt.Sprintf("could not validate quote: %v", err))
		}
		if valid {
			fmt.Println("Signature OK")
		} else {
			fmt.Println("Signature INVALID")
		}
	case "forgeQuote":
		forgeQuoteCmd.Parse(flagSetArgs)
		if len(pcrReadPath) == 0 {
			log.Fatalf("pcrReadPath undefined")
		}
		if len(privKey) == 0 {
			log.Fatalf("privKey undefined")
		}
		if len(quotePath) == 0 {
			log.Fatalf("quotePath undefined")
		}
		if len(sigOutPath) == 0 {
			log.Fatalf("sigOutPath undefined")
		}
		if len(pubKeyPath) == 0 {
			log.Fatalf("pubKeyPath undefined")
		}
		if len(quoteOutPath) == 0 {
			log.Fatalf("quoteOutPath undefined")
		}

		q, err := readQuote(quotePath)
		if err != nil {
			log.Fatalf(err.Error())
		}

		err = forgeQuote(q, pcrReadPath, privKey, pubKeyPath, sigOutPath, quoteOutPath)
		if err != nil {
			log.Fatalf(err.Error())
		}
		fmt.Printf("OK")
	default:
		fmt.Println(fmt.Sprintf("command %s not supported", os.Args[1]))
		flag.Usage()
		os.Exit(1)
	}
	os.Exit(0)
}
