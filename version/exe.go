// Copyright 2017 The Go Authors. All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
)

// An exe is a generic interface to an OS executable (ELF, Mach-O, PE).
type exe interface {
	// Close closes the underlying file.
	Close() error

	// Symbols returns the names of the symbols in the table.
	Symbols() ([]string, error)

	// ReadData reads and returns up to size byte starting at virtual address addr.
	ReadData(addr, size uint64) ([]byte, error)

	// DataStart returns the writable data segment start address.
	DataStart() uint64

	// TextRange returns the text section start and end address.
	TextRange() (uint64, uint64)
}

// openExe opens file and returns it as an exe.
func openExe(file string) (exe, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 16)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	f.Seek(0, 0)
	if bytes.HasPrefix(data, []byte("\x7FELF")) {
		e, err := elf.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &elfExe{f, e}, nil
	}
	if bytes.HasPrefix(data, []byte("MZ")) {
		e, err := pe.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &peExe{f, e}, nil
	}
	if bytes.HasPrefix(data, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(data[1:], []byte("\xFA\xED\xFE")) {
		e, err := macho.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &machoExe{f, e}, nil
	}
	return nil, fmt.Errorf("unrecognized executable format")
}

// elfExe is the ELF implementation of the exe interface.
type elfExe struct {
	os *os.File
	f  *elf.File
}

func (x *elfExe) Close() error {
	return x.os.Close()
}

func (x *elfExe) ReadData(addr, size uint64) ([]byte, error) {
	for _, prog := range x.f.Progs {
		if prog.Vaddr <= addr && addr <= prog.Vaddr+prog.Filesz-1 {
			n := prog.Vaddr + prog.Filesz - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := prog.ReadAt(data, int64(addr-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *elfExe) Symbols() ([]string, error) {
	syms, err := x.f.Symbols()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range syms {
		out = append(out, s.Name)
	}
	return out, nil
}

func (x *elfExe) TextRange() (uint64, uint64) {
	for _, p := range x.f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
			return p.Vaddr, p.Vaddr + p.Filesz
		}
	}
	return 0, 0
}

func (x *elfExe) DataStart() uint64 {
	for _, s := range x.f.Sections {
		if s.Name == ".go.buildinfo" {
			return s.Addr
		}
	}
	for _, p := range x.f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
			return p.Vaddr
		}
	}
	return 0
}

// peExe is the PE (Windows Portable Executable) implementation of the exe interface.
type peExe struct {
	os *os.File
	f  *pe.File
}

func (x *peExe) Close() error {
	return x.os.Close()
}

func (x *peExe) imageBase() uint64 {
	switch oh := x.f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	return 0
}

func (x *peExe) ReadData(addr, size uint64) ([]byte, error) {
	addr -= x.imageBase()
	for _, sect := range x.f.Sections {
		if uint64(sect.VirtualAddress) <= addr && addr <= uint64(sect.VirtualAddress+sect.Size-1) {
			n := uint64(sect.VirtualAddress+sect.Size) - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := sect.ReadAt(data, int64(addr-uint64(sect.VirtualAddress)))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *peExe) Symbols() ([]string, error) {
	var out []string
	for _, s := range x.f.Symbols {
		if s.SectionNumber <= 0 || int(s.SectionNumber) > len(x.f.Sections) {
			continue
		}
		out = append(out, s.Name)
	}
	return out, nil
}

func (x *peExe) TextRange() (uint64, uint64) {
	// Assume text is first non-empty section.
	for _, sect := range x.f.Sections {
		if sect.VirtualAddress != 0 && sect.Size != 0 {
			return uint64(sect.VirtualAddress) + x.imageBase(), uint64(sect.VirtualAddress+sect.Size) + x.imageBase()
		}
	}
	return 0, 0
}

func (x *peExe) DataStart() uint64 {
	// Assume data is first writable section.
	const (
		IMAGE_SCN_CNT_CODE               = 0x00000020
		IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
		IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
		IMAGE_SCN_MEM_EXECUTE            = 0x20000000
		IMAGE_SCN_MEM_READ               = 0x40000000
		IMAGE_SCN_MEM_WRITE              = 0x80000000
		IMAGE_SCN_MEM_DISCARDABLE        = 0x2000000
		IMAGE_SCN_LNK_NRELOC_OVFL        = 0x1000000
		IMAGE_SCN_ALIGN_32BYTES          = 0x600000
	)
	for _, sect := range x.f.Sections {
		if sect.VirtualAddress != 0 && sect.Size != 0 &&
			sect.Characteristics&^IMAGE_SCN_ALIGN_32BYTES == IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE {
			return uint64(sect.VirtualAddress) + x.imageBase()
		}
	}
	return 0
}

// machoExe is the Mach-O (Apple macOS/iOS) implementation of the exe interface.
type machoExe struct {
	os *os.File
	f  *macho.File
}

func (x *machoExe) Close() error {
	return x.os.Close()
}

func (x *machoExe) ReadData(addr, size uint64) ([]byte, error) {
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr <= addr && addr <= seg.Addr+seg.Filesz-1 {
			if seg.Name == "__PAGEZERO" {
				continue
			}
			n := seg.Addr + seg.Filesz - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := seg.ReadAt(data, int64(addr-seg.Addr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *machoExe) Symbols() ([]string, error) {
	var out []string
	for _, s := range x.f.Symtab.Syms {
		out = append(out, s.Name)
	}
	return out, nil
}

func (x *machoExe) TextRange() (uint64, uint64) {
	// Assume text is first non-empty segment.
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if ok && seg.Name != "__PAGEZERO" && seg.Addr != 0 && seg.Filesz != 0 {
			return seg.Addr, seg.Addr + seg.Filesz
		}
	}
	return 0, 0
}

func (x *machoExe) DataStart() uint64 {
	// Look for section named "__go_buildinfo".
	for _, sec := range x.f.Sections {
		if sec.Name == "__go_buildinfo" {
			return sec.Addr
		}
	}
	// Try the first non-empty writable segment.
	const RW = 3
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if ok && seg.Addr != 0 && seg.Filesz != 0 && seg.Prot == RW && seg.Maxprot == RW {
			return seg.Addr
		}
	}
	return 0
}
