package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	CaCertFilepath                                                              string
	CaKeyFilepath                                                               string
	CertFilepath                                                                string
	KeyFilepath                                                                 string
	CsrFilepath                                                                 string
	CsrHashAlgo                                                                 int
	KeyType                                                                     string
	KeyBits                                                                     uint
	Country, Org, OrgUnit, City, Province, Address, ZipCode, Serial, CommonName string

	Command   *cobra.Command
	CaCommand = &cobra.Command{
		Use:   "ca",
		Short: "generate ca",
		RunE:  CaCommandFunc,
	}
	CertCommand = &cobra.Command{
		Use:   "cert",
		Short: "generate certificate use special ca cert",
		RunE:  CertCommandFunc,
	}
	ReqCommand = &cobra.Command{
		Use:   "req",
		Short: "generate certificate request",
		RunE:  ReqCommandFunc,
	}

	SignAlgo = map[string]map[int]x509.SignatureAlgorithm{
		"ecdsa": {
			256: x509.ECDSAWithSHA256,
			384: x509.ECDSAWithSHA384,
			512: x509.ECDSAWithSHA512,
		},
		"rsa": {
			256: x509.SHA256WithRSA,
			384: x509.SHA384WithRSA,
			512: x509.SHA512WithRSA,
		},
	}
)

func init() {
	Command = &cobra.Command{
		DisableAutoGenTag: true,
	}

	Command.Flags().StringVar(&KeyType, "type", "ecdsa", "private key type (ecdsa|rsa)")
	Command.Flags().UintVar(&KeyBits, "bits", 256, "private key bits (rsa:2048,4096|ecdsa:256,384,521)")

	Command.Flags().StringVar(&Country, "country", "", "pkix:Country")
	Command.Flags().StringVar(&Org, "org", "", "pkix:Organization")
	Command.Flags().StringVar(&OrgUnit, "ou", "", "pkix:OrganizationalUnit")
	Command.Flags().StringVar(&City, "city", "", "pkix:Locality")
	Command.Flags().StringVar(&Province, "province", "", "pkix:Province")
	Command.Flags().StringVar(&Address, "address", "", "pkix:StreetAddress")
	Command.Flags().StringVar(&ZipCode, "zipcode", "", "pkix:PostalCode")
	Command.Flags().StringVar(&Serial, "serial", "", "pkix:SerialNumber")
	Command.Flags().StringVar(&CommonName, "cn", "", "pkix:CommonName")

	// CA command flags
	CaCommand.Flags().AddFlagSet(Command.Flags())
	CaCommand.Flags().StringVar(&CaCertFilepath, "cert", "ca.crt", "generated ca certificate filepath")
	CaCommand.Flags().StringVar(&CaKeyFilepath, "key", "ca.key", "generated ca private key filepath")

	// Certificate command flags
	CertCommand.Flags().AddFlagSet(Command.Flags())
	CertCommand.Flags().StringVar(&CaCertFilepath, "ca-cert", "ca.crt", "special CA certificate filepath")
	CertCommand.Flags().StringVar(&CaKeyFilepath, "ca-key", "ca.key", "special CA private key filepath")
	CertCommand.Flags().StringVar(&CertFilepath, "cert", "cert.crt", "generated certificate filepath")
	CertCommand.Flags().StringVar(&KeyFilepath, "key", "cert.key", "generated private key filepath")

	// Generate certificate request flags
	ReqCommand.Flags().AddFlagSet(Command.Flags())
	ReqCommand.Flags().StringVar(&CsrFilepath, "csr", "csr.certificateSignRequest", "generated certificate sign request filepath")
	ReqCommand.Flags().StringVar(&KeyFilepath, "key", "cert.key", "generated private key filepath")
	ReqCommand.Flags().IntVar(&CsrHashAlgo, "hash", 256, "SHA(N), choice:256,384,512")

	Command.AddCommand(CaCommand, CertCommand, ReqCommand)
	Command.Flags().SortFlags = false
}

func main() {
	if err := Command.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func CaCommandFunc(*cobra.Command, []string) error {
	privateKey, err := generatePrivateKey(KeyType, int(KeyBits))
	if err != nil {
		return err
	}
	encodedPrivateKey, header, err := encodePrivateKey(privateKey)
	if err != nil {
		return err
	}

	pkixItem := pkix.Name{
		Country:            []string{Country},
		Organization:       []string{Org},
		OrganizationalUnit: []string{OrgUnit},
		Locality:           []string{City},
		Province:           []string{Province},
		StreetAddress:      []string{Address},
		PostalCode:         []string{ZipCode},
		SerialNumber:       Serial,
		CommonName:         CommonName,
	}

	caCert := createCertificate(pkixItem, nil, true)

	cert := sign(caCert, caCert, privateKey, nil)

	writeFile(CaCertFilepath, toPEMBytes(cert, "CERTIFICATE"))
	writeFile(CaKeyFilepath, toPEMBytes(encodedPrivateKey, header))

	fmt.Printf(
		"Generated certificate and private key at [%s], [%s] \n",
		getFilepath(CaCertFilepath),
		getFilepath(CaKeyFilepath),
	)

	return nil
}
func CertCommandFunc(*cobra.Command, []string) error {
	var (
		realCaCertFilepath = getFilepath(CaCertFilepath)
		realCaKeyFilepath  = getFilepath(CaKeyFilepath)
	)
	if !fileExists(realCaCertFilepath) {
		return errors.New("CA cert not found")
	}
	if !fileExists(realCaKeyFilepath) {
		return errors.New("CA private key not found")
	}
	CaCertByte, err := os.ReadFile(realCaCertFilepath)
	if err != nil {
		return err
	}
	CaKeyByte, err := os.ReadFile(realCaKeyFilepath)
	if err != nil {
		return err
	}
	CaCertBlock, _ := pem.Decode(CaCertByte)
	CaKeyBlock, _ := pem.Decode(CaKeyByte)

	CaPrivateKey, err := decodePrivateKey(CaKeyBlock.Bytes)
	if err != nil {
		return err
	}
	CaCert, err := x509.ParseCertificate(CaCertBlock.Bytes)
	if err != nil {
		return err
	}

	privateKey, err := generatePrivateKey(KeyType, int(KeyBits))
	if err != nil {
		return err
	}
	encodedPrivateKey, header, err := encodePrivateKey(privateKey)
	if err != nil {
		return err
	}
	names := strings.Split(strings.ReplaceAll(CommonName, " ", ""), ",")
	pkixItem := pkix.Name{
		Country:            []string{Country},
		Organization:       []string{Org},
		OrganizationalUnit: []string{OrgUnit},
		Locality:           []string{City},
		Province:           []string{Province},
		StreetAddress:      []string{Address},
		PostalCode:         []string{ZipCode},
		SerialNumber:       Serial,
		CommonName:         names[0],
	}

	newCert := createCertificate(pkixItem, names[1:], false)

	cert := sign(newCert, CaCert, privateKey, CaPrivateKey.(crypto.Signer))

	writeFile(CertFilepath, toPEMBytes(cert, "CERTIFICATE"))
	writeFile(KeyFilepath, toPEMBytes(encodedPrivateKey, header))

	fmt.Printf(
		"Generated certificate , private key at [%s] [%s] use CA key [%s]\n",
		getFilepath(CertFilepath),
		getFilepath(KeyFilepath),
		realCaKeyFilepath,
	)

	return nil
}
func ReqCommandFunc(*cobra.Command, []string) error {

	privateKey, _ := generatePrivateKey(KeyType, int(KeyBits))

	signAlgo, ok := SignAlgo[KeyType][CsrHashAlgo]
	if !ok {
		return errors.New("invalid hash algo, accept: 256,384 or 512")
	}

	dns := strings.Split(strings.ReplaceAll(CommonName, " ", ""), ",")

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{Country},
			Organization:       []string{Org},
			OrganizationalUnit: []string{OrgUnit},
			Locality:           []string{City},
			Province:           []string{Province},
			StreetAddress:      []string{Address},
			PostalCode:         []string{ZipCode},
			CommonName:         dns[0],
		},
		DNSNames:           dns,
		SignatureAlgorithm: signAlgo,
	}

	request, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return err
	}

	encodedPrivateKey, header, err := encodePrivateKey(privateKey)
	if err != nil {
		return err
	}

	writeFile(CsrFilepath, toPEMBytes(request, "CERTIFICATE REQUEST"))
	writeFile(KeyFilepath, toPEMBytes(encodedPrivateKey, header))

	return nil
}

func generatePrivateKey(keyType string, bitSize int) (crypto.Signer, error) {
	var privateKey crypto.Signer
	var err error
	switch keyType {
	case "ecdsa":
		var curve elliptic.Curve
		switch bitSize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		}
		privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "rsa":
		privateKey, err = rsa.GenerateKey(rand.Reader, bitSize)
	default:
		return nil, errors.New("unknown key type")
	}
	return privateKey, err
}

func fileExists(file string) bool {
	_, err := os.Stat(getFilepath(file))
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func getFilepath(filename string) string {
	filename, _ = filepath.Abs(filename)
	return filename
}

func sign(cert, cacert *x509.Certificate, priv1, priv2 crypto.Signer) []byte {
	pub := priv1.Public()
	priv := priv1

	if priv2 != nil {
		priv = priv2
	}

	certificate, err := x509.CreateCertificate(rand.Reader, cert, cacert, pub, priv)
	if err != nil {
		log.Fatalln(err)
	}

	return certificate
}

func createCertificate(pkixItem pkix.Name, extraNames []string, isCa bool) *x509.Certificate {

	keyUsage := x509.KeyUsageDigitalSignature

	if isCa {
		keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject:      pkixItem,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         isCa,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		CRLDistributionPoints: []string{},
	}

	if extraNames != nil {
		certificate.DNSNames = extraNames
	}

	return certificate
}

func writeFile(filename string, content []byte) {
	_ = os.WriteFile(filename, content, 0755)
}

func toPEMBytes(crt []byte, Type string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  Type,
		Bytes: crt,
	})
}
func encodePrivateKey(signer crypto.Signer) (encoded []byte, header string, err error) {
	if pri, ok := signer.(*rsa.PrivateKey); ok {
		encoded = x509.MarshalPKCS1PrivateKey(pri)
		header = "RSA PRIVATE KEY"
	} else if pri, ok := signer.(*ecdsa.PrivateKey); ok {
		encoded, err = x509.MarshalECPrivateKey(pri)
		if err != nil {
			return nil, "", err
		}
		header = "EC PRIVATE KEY"
	} else {
		return nil, "", errors.New("unknown private key type when toPEMBytes private key")
	}

	return encoded, header, nil

}

func decodePrivateKey(der []byte) (crypto.Signer, error) {

	if signer, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return signer, nil
	} else if signer, err := x509.ParseECPrivateKey(der); err == nil {
		return signer, nil
	}

	return nil, errors.New("parse private key fail")

}
