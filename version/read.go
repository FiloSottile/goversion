// Copyright 2017 The Go Authors. All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package version reports the Go version used to build program executables.
package version

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Version is the information reported by ReadExe.
type Version struct {
	Release        string // Go version (runtime.Version in the program)
	ModuleInfo     string // program's module information
	BoringCrypto   bool   // program uses BoringCrypto
	StandardCrypto bool   // program uses standard crypto (replaced by BoringCrypto)
	FIPSOnly       bool   // program imports "crypto/tls/fipsonly"
}

// ReadExe reports information about the Go version used to build
// the program executable named by file.
func ReadExe(file string) (Version, error) {
	var v Version
	f, err := openExe(file)
	if err != nil {
		return v, err
	}
	defer f.Close()

	syms, _ := f.Symbols()
	for _, name := range syms {
		if strings.HasPrefix(name, "runtime.") && strings.HasSuffix(name, "$descriptor") {
			defer func() {
				if v.Release == "" || v.Release == "unknown Go version" {
					v.Release = "gccgo (version unknown)"
					err = nil
				}
			}()
		}
		if strings.Contains(name, "_Cfunc__goboringcrypto_") || name == "crypto/internal/boring/sig.BoringCrypto" {
			v.BoringCrypto = true
		}
		if name == "crypto/internal/boring/sig.FIPSOnly" {
			v.FIPSOnly = true
		}
		for _, re := range standardCryptoNames {
			if re.MatchString(name) {
				v.StandardCrypto = true
			}
		}
		if name == "crypto/internal/boring/sig.StandardCrypto" {
			v.StandardCrypto = true
		}
	}

	if err := findCryptoSigs(&v, f); err != nil {
		return v, err
	}

	// The build info blob left by the linker is identified by
	// a 16-byte header, consisting of buildInfoMagic (14 bytes),
	// the binary's pointer size (1 byte),
	// and whether the binary is big endian (1 byte).
	var buildInfoMagic = []byte("\xff Go buildinf:")

	// Read the first 64kB of text to find the build info blob.
	text := f.DataStart()
	data, err := f.ReadData(text, 64*1024)
	if err != nil {
		return v, err
	}
	for ; !bytes.HasPrefix(data, buildInfoMagic); data = data[32:] {
		if len(data) < 32 {
			return v, errors.New("not a Go executable")
		}
	}

	// Decode the blob.
	ptrSize := int(data[14])
	bigEndian := data[15] != 0
	var bo binary.ByteOrder
	if bigEndian {
		bo = binary.BigEndian
	} else {
		bo = binary.LittleEndian
	}
	var readPtr func([]byte) uint64
	if ptrSize == 4 {
		readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
	} else {
		readPtr = bo.Uint64
	}
	v.Release = readString(f, ptrSize, readPtr, readPtr(data[16:]))
	if v.Release == "" {
		v.Release = "unknown Go version"
	}
	v.ModuleInfo = readString(f, ptrSize, readPtr, readPtr(data[16+ptrSize:]))
	if len(v.ModuleInfo) >= 33 && v.ModuleInfo[len(v.ModuleInfo)-17] == '\n' {
		// Strip module framing.
		v.ModuleInfo = v.ModuleInfo[16 : len(v.ModuleInfo)-16]
	} else {
		v.ModuleInfo = ""
	}

	return v, nil
}

// readString returns the string at address addr in the executable x.
func readString(x exe, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := x.ReadData(addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := x.ReadData(dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}

var re = regexp.MustCompile

var standardCryptoNames = []*regexp.Regexp{
	re(`^crypto/sha1\.\(\*digest\)`),
	re(`^crypto/sha256\.\(\*digest\)`),
	re(`^crypto/rand\.\(\*devReader\)`),
	re(`^crypto/rsa\.encrypt$`),
	re(`^crypto/rsa\.decrypt$`),
}

// Code signatures that indicate BoringCrypto or crypto/internal/fipsonly.
// These are not byte literals in order to avoid the actual
// byte signatures appearing in the goversion binary,
// because on some systems you can't tell rodata from text.
var (
	sigBoringCrypto, _   = hex.DecodeString("EB1DF448F44BF4B332F52813A3B450D441CC2485F001454E92101B1D2F1950C3")
	sigStandardCrypto, _ = hex.DecodeString("EB1DF448F44BF4BAEE4DFA9851CA56A91145E83E99C59CF911CB8E80DAF12FC3")
	sigFIPSOnly, _       = hex.DecodeString("EB1DF448F44BF4363CB9CE9D68047D31F28D325D5CA5873F5D80CAF6D6151BC3")
)

func findCryptoSigs(v *Version, f exe) error {
	const maxSigLen = 1 << 10
	start, end := f.TextRange()
	for addr := start; addr < end; {
		size := uint64(1 << 20)
		if end-addr < size {
			size = end - addr
		}
		data, err := f.ReadData(addr, size)
		if err != nil {
			return fmt.Errorf("reading text: %v", err)
		}
		if haveSig(data, sigBoringCrypto) {
			v.BoringCrypto = true
		}
		if haveSig(data, sigFIPSOnly) {
			v.FIPSOnly = true
		}
		if haveSig(data, sigStandardCrypto) {
			v.StandardCrypto = true
		}
		if addr+size < end {
			size -= maxSigLen
		}
		addr += size
	}
	return nil
}

func haveSig(data, sig []byte) bool {
	const align = 16
	for {
		i := bytes.Index(data, sig)
		if i < 0 {
			return false
		}
		if i&(align-1) == 0 {
			return true
		}
		// Found unaligned match; unexpected but
		// skip to next aligned boundary and keep searching.
		data = data[(i+align-1)&^(align-1):]
	}
}
