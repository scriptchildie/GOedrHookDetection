package main

import (
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"unsafe"

	"github.com/jedib0t/go-pretty/v6/table"
	"golang.org/x/sys/windows"
)

type IMAGE_EXPORT_DIRECTORY struct { //offsets
	Characteristics       uint32 // 0x0
	TimeDateStamp         uint32 // 0x4
	MajorVersion          uint16 // 0x8
	MinorVersion          uint16 // 0xa
	Name                  uint32 // 0xc
	Base                  uint32 // 0x10
	NumberOfFunctions     uint32 // 0x14
	NumberOfNames         uint32 // 0x18
	AddressOfFunctions    uint32 // 0x1c
	AddressOfNames        uint32 // 0x20
	AddressOfNameOrdinals uint32 // 0x24
}
type Exportfunc struct {
	funcRVA         uint32  // relative address to the base address of the dll
	functionAddress uintptr // absolute address
	name            string  // name of the exported function
	syscallno       uint16  // SSN
	trampoline      uintptr // syscall ;ret; address location
	isHooked        bool    // Is the function hooked?
}

type dllstruct struct {
	name                   string
	address                uintptr
	exportDirectoryAddress uintptr
	exportDirectory        IMAGE_EXPORT_DIRECTORY
	exportedNtFunctions    []Exportfunc
	exportedZwFunctions    []Exportfunc
}

func main() {
	PrintModules()
	dll, err := GetStructOfLoadedDll("ntdll.dll")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("\n[+] Base Address of dll %s is 0x%x\n\n", dll.name, dll.address)

	fmt.Printf("[+] Export Table Address 0x%x\n\n", dll.getExportTableAddress())
	dll.GetImageExportDirectory()
	dll.getExportTableAddress()
	dll.GetModuleExports()
	dll.PrintExports()
}

func (dll *dllstruct) PrintExports() {
	noPrint := []string{"NtQuerySystemTime", "ZwQuerySystemTime"}

	tNt := table.NewWriter()
	tNt.AppendHeader(table.Row{"#", "Function Address", "Function Name", "SysCallNo (SSN)", "Trampoline", "Hooked?"})
	for i, fun := range dll.exportedNtFunctions {
		if slices.Contains(noPrint, fun.name) {
			continue
		}
		tNt.AppendRow(table.Row{i, fmt.Sprintf("0x%x", fun.functionAddress), fun.name, fmt.Sprintf("0x%x", fun.syscallno), fmt.Sprintf("0x%x", fun.trampoline), fun.isHooked})
	}
	tZw := table.NewWriter()
	tZw.AppendHeader(table.Row{"#", "Function Address", "Function Name", "SysCallNo (SSN)", "Trampoline", "Hooked?"})
	for i, fun := range dll.exportedZwFunctions {
		if slices.Contains(noPrint, fun.name) {
			continue
		}
		tZw.AppendRow(table.Row{i, fmt.Sprintf("0x%x", fun.functionAddress), fun.name, fmt.Sprintf("0x%x", fun.syscallno), fmt.Sprintf("0x%x", fun.trampoline), fun.isHooked})
	}
	fmt.Println(tNt.Render())
	fmt.Println(tZw.Render())
}

func (fun *Exportfunc) GetSyscallNumbers(address uintptr) {

	funcbytes := (*[5]byte)(unsafe.Pointer(fun.functionAddress))[:]

	if funcbytes[0] == 0x4c && funcbytes[1] == 0x8b && funcbytes[2] == 0xd1 && funcbytes[3] == 0xb8 { // Check if the function is hooked.
		fun.syscallno = *(*uint16)(unsafe.Pointer(&funcbytes[4])) // Get Syscall Number
		fun.isHooked = false
	} else {
		fun.syscallno = 0xffff // when hooked set the syscall number 0xff
		fun.isHooked = true
	}

	//fmt.Printf("Func RVA: %x , nameRVA: %x , name: %s, syscallno : %x\n", exFunc.funcRVA, exFunc.nameRVA, exFunc.name, exFunc.syscallno)

}

func (dll *dllstruct) GetModuleExports() {

	exclusions := []string{"NtdllDefWindowProc_A", "NtdllDefWindowProc_W", "NtdllDialogWndProc_A", "NtdllDialogWndProc_W", "NtGetTickCount"}

	var absAddress uintptr

	for i := 0; i < int(dll.exportDirectory.NumberOfNames); i++ {
		funcRVA := *((*uint32)(unsafe.Pointer(dll.address + (uintptr(dll.exportDirectory.AddressOfFunctions) + uintptr((i+1)*0x4)))))
		nameRVA := *((*uint32)(unsafe.Pointer(dll.address + (uintptr(dll.exportDirectory.AddressOfNames) + uintptr(i*0x4)))))
		nameAddr := dll.address + uintptr(nameRVA)
		nameRVAbyte := (*[4]byte)(unsafe.Pointer(nameAddr))[:]
		name := windows.BytePtrToString(&nameRVAbyte[0])

		absAddress = dll.address + uintptr(funcRVA)
		for j := 0; j < 100; j++ {
			if *(*byte)(unsafe.Pointer(absAddress)) == 0x0f {
				if *(*byte)(unsafe.Pointer(absAddress + 1)) == 0x05 {
					if *(*byte)(unsafe.Pointer(absAddress + 2)) == 0xc3 {
						break
					}
				}
			}
			absAddress += 1
		}

		if strings.HasPrefix(name, "Nt") && !slices.Contains(exclusions, name) {
			funcExp := Exportfunc{
				funcRVA:         funcRVA,
				functionAddress: dll.address + uintptr(funcRVA),
				name:            name,
				trampoline:      absAddress,
			}
			funcExp.GetSyscallNumbers(dll.address)
			dll.exportedNtFunctions = append(dll.exportedNtFunctions, funcExp)
		}

		if strings.HasPrefix(name, "Zw") {
			funcExp := Exportfunc{
				funcRVA:         funcRVA,
				functionAddress: dll.address + uintptr(funcRVA),
				name:            name,
				trampoline:      absAddress,
			}
			funcExp.GetSyscallNumbers(dll.address)
			dll.exportedZwFunctions = append(dll.exportedZwFunctions, funcExp)
		}

	}
	sort.SliceStable(dll.exportedNtFunctions, func(i, j int) bool {
		return (dll.exportedNtFunctions)[i].funcRVA < (dll.exportedNtFunctions)[j].funcRVA
	})
	sort.SliceStable(dll.exportedZwFunctions, func(i, j int) bool {
		return (dll.exportedZwFunctions)[i].funcRVA < (dll.exportedZwFunctions)[j].funcRVA
	})
}

// Get Image Export directory. We are interested in
// - AddressofFunctions
// - AddressOfNames
// - AddressOFNameOrdinals (maybe in the future)
// - Number of functions
func (dll *dllstruct) GetImageExportDirectory() {

	dll.exportDirectory.Characteristics = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress)))
	dll.exportDirectory.TimeDateStamp = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x4)))
	dll.exportDirectory.MajorVersion = *((*uint16)(unsafe.Pointer(dll.exportDirectoryAddress + 0x8)))
	dll.exportDirectory.MinorVersion = *((*uint16)(unsafe.Pointer(dll.exportDirectoryAddress + 0xa)))
	dll.exportDirectory.Name = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0xc)))
	dll.exportDirectory.Base = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x10)))
	dll.exportDirectory.NumberOfFunctions = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x14)))
	dll.exportDirectory.NumberOfNames = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x18)))
	dll.exportDirectory.AddressOfFunctions = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x1c)))
	dll.exportDirectory.AddressOfNames = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x20)))
	dll.exportDirectory.AddressOfNameOrdinals = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x24)))

}

func (dll *dllstruct) getExportTableAddress() uintptr {
	e_lfanew := *((*uint32)(unsafe.Pointer(dll.address + 0x3c)))
	ntHeader := dll.address + uintptr(e_lfanew)
	fileHeader := ntHeader + 0x4
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
	optionalHeader := fileHeader + 0x14 // 0x14 is the size of the image_file_header struct
	exportDir := optionalHeader + 0x70  // offset to export table
	exportDirOffset := *((*uint32)(unsafe.Pointer(exportDir)))
	dll.exportDirectoryAddress = dll.address + uintptr(exportDirOffset)
	return dll.exportDirectoryAddress
}

func GetStructOfLoadedDll(name string) (dllstruct, error) {
	modules := ListDllFromPEB()
	for _, module := range modules {
		if module.name == name {
			return module, nil
		}

	}
	return dllstruct{}, fmt.Errorf("dll not Found")
}

func PrintModules() {
	t := table.NewWriter()
	fmt.Printf("---------------------------------------------\nLoaded modules in current process\n")
	t.AppendHeader(table.Row{"#", "DLL Name", "Address"})

	for i, module := range ListDllFromPEB() {
		t.AppendRow(table.Row{i, module.name, fmt.Sprintf("0x%x", module.address)})
	}
	fmt.Println(t.Render())
}

// adds all loaded modules and their base addresses in a slice
func ListDllFromPEB() []dllstruct {

	peb := windows.RtlGetCurrentPeb()
	moduleList := peb.Ldr.InMemoryOrderModuleList
	a := moduleList.Flink
	loadedModules := []dllstruct{}
	for {

		listentry := uintptr(unsafe.Pointer(a))
		// -0x10 beginning of the _LDR_DATA_TABLE_ENTRY_ structure
		// +0x30 Dllbase address
		// +0x58 +0x8 address holding the address pointing to base dllname
		// offsets different for 32-bit processes
		DllBase := uintptr(listentry) - 0x10 + 0x30
		BaseDllName := uintptr(listentry) - 0x10 + 0x58 + 0x8

		v := *((*uintptr)(unsafe.Pointer(BaseDllName)))
		//fmt.Printf("%p\n", (unsafe.Pointer(v))) // prints the address that holds the dll name

		s := ((*uint16)(unsafe.Pointer(v))) // turn uintptr to *uint16
		dllNameStr := windows.UTF16PtrToString(s)
		if dllNameStr == "" {
			break
		}

		dllbaseaddr := *((*uintptr)(unsafe.Pointer(DllBase)))
		//fmt.Printf("%p\n", (unsafe.Pointer(dllbaseaddr))) // prints the dll base addr
		loadedModules = append(loadedModules, dllstruct{
			name:                   dllNameStr,
			address:                dllbaseaddr,
			exportDirectoryAddress: 0,
			exportDirectory:        IMAGE_EXPORT_DIRECTORY{Characteristics: 0, TimeDateStamp: 0, MajorVersion: 0, MinorVersion: 0, Name: 0, Base: 0, NumberOfFunctions: 0, NumberOfNames: 0, AddressOfFunctions: 0, AddressOfNames: 0, AddressOfNameOrdinals: 0},
			exportedNtFunctions:    []Exportfunc{},
			exportedZwFunctions:    []Exportfunc{},
		})
		a = a.Flink
	}

	return loadedModules
}
