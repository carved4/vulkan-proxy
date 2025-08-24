# vulkan-1.dll proxy execution poc

a proof-of-concept demonstrating proxy execution in `vulkan-1.dll`.

## credits

original research and writeup by [@whokilleddb](https://twitter.com/whokilleddb).
the details can be found here: https://github.com/whokilleddb/function-collections/tree/main/hijack_callbacks/vkAllocateMemory

## the bug

this behavior exists in multiple exported functions within `vulkan-1.dll`, such as `vkAllocateMemory` and `vkCreateSamplerYcbcrConversion`. it stems from a flawed argument validation mechanism. (literally all the vk* functions can be used, just identify the rax_1[..] value in the disassembly of target func and set your function ptr to that index in the crafted struct that correlates to said value, as long as checksum is in pos 0 you will satisfy the check and it will reach your function ptr in the vtable to execute)

the functions expect a pointer to a structure as an argument. the code proceeds to check for a magic value (`0x10aded040410aded`) within a nested structure. if this magic value is found, the code assumes the structure is legitimate and performs an indirect call to a function pointer located at a hardcoded offset within that same structure.

by carefully crafting a fake structure containing the magic value and a pointer to our own shellcode at the correct offset, we can hijack the control flow of the application.

## how the poc works

this proof-of-concept is written in go and heavily leverages my wincall pkg to avoid the go -> c func pointer abi mismatch :3

1.  loading `vulkan-1.dll` into the process memory.
2.  finding the address of a function (`vkCreateSamplerYcbcrConversion`).
3.  creating a specially crafted go struct that mimics the expected structure. this struct contains the magic number (`0x10aded040410aded`) and a pointer to our payload at the required offset (in this case, index 132 of a function table).
4.  calling the function with a pointer to our crafted struct.

this triggers the behavior, causing the function to execute our payload.

the poc showcases two different payloads:
1.  a simple call to `user32!MessageBoxW` to display a message box.
2.  a more advanced technique that uses this proxy as a gadget to make direct syscalls. this allows the poc to allocate memory, write shellcode, mark it as executable, and run it in a new thread, all while bypassing common user-mode api hooking mechanisms used by security products. the shellcode in this example launches `calc.exe`.
int64_t* rax_1  {Register rax}
int64_t* arg1  {Register rcx}
```
1800358e0    {
1800358e0        if (arg1)
1800358e7        {
1800358e9            int64_t* rax_1 = *(uint64_t*)arg1;
1800358e9            
1800358fe            if (rax_1 && *(uint64_t*)rax_1 == 0x10aded040410aded)
1800358fe            {
180035900                rax_1[7];
18003590f                /* tailcall */
18003590f                return _guard_dispatch_icall_nop(arg1);
1800358fe            }
1800358e7        }
1800358e7        
180035923        sub_180030f60(nullptr, 0x188, 0, "vkAllocateMemory: Invalid device…");
180035928        sub_18006c41c();
180035928        /* no return */
1800358e0    }
```
