package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func removeGREASE(list []uint16) []uint16 {
	var filtered []uint16
	for _, v := range list {
		if !isGREASE(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
func isGREASE(v uint16) bool {
	greaseValues := []uint16{0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
	for _, g := range greaseValues {
		if v == g {
			return true
		}
	}
	return false
}
func Ja4_a(info *tls.ClientHelloInfo) string {
	tlsVersion := "00"
	supportedVersions := removeGREASE(info.SupportedVersions)
	switch supportedVersions[0] {
	case tls.VersionTLS13:
		tlsVersion = "13"
	case tls.VersionTLS12:
		tlsVersion = "12"
	case tls.VersionTLS11:
		tlsVersion = "11"
	case tls.VersionTLS10:
		tlsVersion = "10"
	}

	sni := "i"
	if info.ServerName != "" {
		sni = "d"
	}

	cipherSuites := removeGREASE(info.CipherSuites)
	cipherSuitesLen := min(len(cipherSuites), 99)

	extensions := removeGREASE(info.Extensions)
	extensionsLen := min(len(extensions), 99)

	alpnProtocol := "00"
	if info.SupportedProtos[0] != "" {
		negotiatedProtocol := info.SupportedProtos[0]
		alpnProtocol = string(negotiatedProtocol[0]) + string(negotiatedProtocol[len(negotiatedProtocol)-1])
	}
	return fmt.Sprintf("t%s%s%d%d%s", tlsVersion, sni, cipherSuitesLen, extensionsLen, alpnProtocol)
}
func Ja4_b(info *tls.ClientHelloInfo, ja4_o bool) string {
	cipherSuites := removeGREASE(info.CipherSuites)
	if len(cipherSuites) > 0 {
		var cipherSuitesHex []string
		for _, cipherSuite := range cipherSuites {
			cipherSuitesHex = append(cipherSuitesHex, fmt.Sprintf("%04x", cipherSuite))
		}
		if !ja4_o {
			sort.Strings(cipherSuitesHex)
		}
		sum := sha256.Sum256([]byte(strings.Join(cipherSuitesHex, ",")))
		return hex.EncodeToString(sum[:6])
	}
	return "000000000000"
}
func ja4_br(info *tls.ClientHelloInfo, ja4_o bool) string {
	cipherSuites := removeGREASE(info.CipherSuites)
	var cipherSuitesHex []string
	for _, cipherSuite := range cipherSuites {
		cipherSuitesHex = append(cipherSuitesHex, fmt.Sprintf("%04x", cipherSuite))
	}
	if !ja4_o {
		sort.Strings(cipherSuitesHex)
	}
	return strings.Join(cipherSuitesHex, ",")
}
func Ja4_c(info *tls.ClientHelloInfo, ja4_o bool) string {
	extensions := removeGREASE(info.Extensions)
	var extensionsHex []string
	for _, ext := range extensions {
		if ja4_o || (ext != 0x00 && ext != 0x0010) {
			extensionsHex = append(extensionsHex, fmt.Sprintf("%04x", ext))
		}
	}
	if !ja4_o {
		sort.Strings(extensionsHex)
	}
	if len(extensionsHex) == 0 {
		return "000000000000"
	}
	extensionsStr := strings.Join(extensionsHex, ",")
	if len(info.SignatureSchemes) > 0 {
		var signatureSchemesHex []string
		for _, v := range info.SignatureSchemes {
			signatureSchemesHex = append(signatureSchemesHex, fmt.Sprintf("%04x", uint16(v)))
		}
		extensionsStr += "_" + strings.Join(signatureSchemesHex, ",")
	}
	sum := sha256.Sum256([]byte(extensionsStr))
	return hex.EncodeToString(sum[:6])
}
func ja4_cr(info *tls.ClientHelloInfo, ja4_o bool) string {
	extensions := removeGREASE(info.Extensions)
	var extensionsHex []string
	for _, ext := range extensions {
		if ja4_o || (ext != 0x00 && ext != 0x0010) {
			extensionsHex = append(extensionsHex, fmt.Sprintf("%04x", ext))
		}
	}
	if !ja4_o {
		sort.Strings(extensionsHex)
	}
	extensionsStr := strings.Join(extensionsHex, ",")
	if len(info.SignatureSchemes) > 0 {
		var signatureSchemesHex []string
		for _, v := range info.SignatureSchemes {
			signatureSchemesHex = append(signatureSchemesHex, fmt.Sprintf("%04x", uint16(v)))
		}
		extensionsStr += "_" + strings.Join(signatureSchemesHex, ",")
	}
	return extensionsStr
}
func Ja4(info *tls.ClientHelloInfo, ja4_o, ja4_r bool) string {
	if ja4_r {
		return fmt.Sprintf("%s_%s_%s", Ja4_a(info), ja4_br(info, ja4_o), ja4_cr(info, ja4_o))
	} else {
		return fmt.Sprintf("%s_%s_%s", Ja4_a(info), Ja4_b(info, ja4_o), Ja4_c(info, ja4_o))
	}
}
