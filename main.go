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
	command := os.Args[flag.NFlag()+1]

	var flagSet *flag.FlagSet

	switch command {
	case "validateKeypair":
		flagSet = validateKeypairCmd
	case "validateQuote":
		flagSet = validateQuoteCmd
	case "forgeQuote":
		flagSet = forgeQuoteCmd
	}

	if flagSet == nil {
		log.Fatalf("unsupported command %s", command)
	}

	flagSet.Parse(flagSetArgs)
	flagSet.VisitAll(func(f *flag.Flag) {
		if f.Value.String() == "" {
			log.Fatalf("%s is required for command %s", f.Name, command)
		}
	})

	switch command {
	case "validateKeypair":
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
		q, err := readQuote(quotePath)
		if err != nil {
			log.Fatalf(err.Error())
		}
		m, err := json.MarshalIndent(q, " ", " ")
		if err != nil {
			log.Fatalf(fmt.Sprintf("could not marshal result: %v", err))
		}
		fmt.Println(string(m))
		valid, err := validateQuote(q, sigPath, privKey, pubKeyPath, pcrReadPath)
		if err != nil {
			log.Fatalf(fmt.Sprintf("could not validate quote: %v", err))
		}
		if valid {
			fmt.Println("OK")
		} else {
			fmt.Println("INVALID")
			os.Exit(1)
		}
	case "forgeQuote":
		q, err := readQuote(quotePath)
		if err != nil {
			log.Fatalf(err.Error())
		}

		err = forgeQuote(q, pcrReadPath, privKey, pubKeyPath, sigOutPath, quoteOutPath)
		if err != nil {
			log.Fatalf(err.Error())
		}
	default:
		fmt.Println(fmt.Sprintf("command %s not supported", os.Args[1]))
		flag.Usage()
		os.Exit(1)
	}
	os.Exit(0)
}
