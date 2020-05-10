package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

func help() {
	fmt.Println("Supported commads:")
	fmt.Println("\tvalidateKeypair\t\tValidates EC keypar")
	fmt.Println("\tvalidateQuote\t\tValidate a quote given an EC public key")
}

func main() {

	var (
		privKey, pubKeyPath, privKeyPath string
		quotePath, pcrReadPath, sigPath  string
	)

	validateKeypairCmd := flag.NewFlagSet("validateKeypair", flag.ExitOnError)
	validateKeypairCmd.StringVar(&privKey, "privKey", "", "decimal representation of the private key")
	validateKeypairCmd.StringVar(&pubKeyPath, "pubKeyPath", "", "path of the public key file in pem format")

	validateQuoteCmd := flag.NewFlagSet("validateQuote", flag.ExitOnError)
	validateQuoteCmd.StringVar(&quotePath, "quotePath", "", "path of the quote")
	validateQuoteCmd.StringVar(&sigPath, "sigPath", "", "path of the signature")
	validateQuoteCmd.StringVar(&pcrReadPath, "pcrReadPath", "", "path of a file containing PCR readings")

	forgeQuoteCmd := flag.NewFlagSet("forgeQuote", flag.ExitOnError)
	forgeQuoteCmd.StringVar(&privKeyPath, "quotePath", "", "path of the quote")

	if len(os.Args) < 2 {
		log.Println("expected command as argument")
		help()
		os.Exit(1)
	}

	switch os.Args[1] {

	case "validateKeypair":
		validateKeypairCmd.Parse(os.Args[2:])
		kv, err := validateKeypair(privKey, pubKeyPath)
		if err != nil {
			log.Fatalf(err.Error())
		}
		m, err := json.MarshalIndent(kv, " ", " ")
		if err != nil {
			log.Fatalf(fmt.Sprintf("could not marshal result: %v", err))
		}
		fmt.Printf(string(m))
		os.Exit(1)
	case "validateQuote":
		validateQuoteCmd.Parse(os.Args[2:])
		q, err := readQuote(quotePath)
		if err != nil {
			log.Fatalf(err.Error())
		}
		m, err := json.MarshalIndent(q, " ", " ")
		if err != nil {
			log.Fatalf(fmt.Sprintf("could not marshal result: %v", err))
		}
		fmt.Printf(string(m))
		_, err = validateQuote(q, "")
		if err != nil {
			log.Fatalf(fmt.Sprintf("could not validate quote: %v", err))
		}
		os.Exit(1)
	case "forgeQuote":
		log.Fatalf("not supported yet")
	default:
		fmt.Println(fmt.Sprintf("command %s not supported", os.Args[1]))
		help()
		os.Exit(1)
	}
}
