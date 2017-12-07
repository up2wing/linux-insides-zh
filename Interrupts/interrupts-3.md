中断和中断处理. Part 3.Interrupts and Interrupt Handling. Part 3.
================================================================================

异常处理Exception Handling
--------------------------------------------------------------------------------

这是关于Linux 内核中断和异常处理[章](http://0xax.gitbooks.io/linux-insides/content/interrupts/index.html)的第三部分，在上一[部分](http://0xax.gitbooks.io/linux-insides/content/interrupts/index.html)中我们在源码文件 [arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blame/master/arch/x86/kernel/setup.c) 中的 `setup_arch` 函数停止了。This is the third part of the [chapter](http://0xax.gitbooks.io/linux-insides/content/interrupts/index.html) about an interrupts and an exceptions handling in the Linux kernel and in the previous [part](http://0xax.gitbooks.io/linux-insides/content/interrupts/index.html) we stopped at the `setup_arch` function from the [arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blame/master/arch/x86/kernel/setup.c) source code file.

我们已经知道了，这个函数执行和具体架构相关东西的初始化。在我们的例子中，`setup_arch` 函数执行 [x86_64](https://en.wikipedia.org/wiki/X86-64)  架构相关的初始化。`setup_arch` 是个大函数，在上一部分我们停在了设置下面两个异常的异常处理中：We already know that this function executes initialization of architecture-specific stuff. In our case the `setup_arch` function does [x86_64](https://en.wikipedia.org/wiki/X86-64) architecture related initializations. The `setup_arch` is big function, and in the previous part we stopped on the setting of the two exceptions handlers for the two following exceptions:

* `#DB` - 调试异常，将控制从中断的进程传递到调试处理程序；debug exception, transfers control from the interrupted process to the debug handler;
* `#BP` - 由 `int 3` 指令引发的断点异常。breakpoint exception, caused by the `int 3` instruction.

这些异常允许 `x86_64` 架构具有早期异常处理（功能），以通过 [kgdb](https://en.wikipedia.org/wiki/KGDB) 进行调试。These exceptions allow the `x86_64` architecture to have early exception processing for the purpose of debugging via the [kgdb](https://en.wikipedia.org/wiki/KGDB).

你应该记得，我们在 `early_trap_init` 函数中设置这些异常：As you can remember we set these exceptions handlers in the `early_trap_init` function:

```C
void __init early_trap_init(void)
{
        set_intr_gate_ist(X86_TRAP_DB, &debug, DEBUG_STACK);
        set_system_intr_gate_ist(X86_TRAP_BP, &int3, DEBUG_STACK);
        load_idt(&idt_descr);
}
```

该函数在 [arch/x86/kernel/traps.c](https://github.com/torvalds/linux/tree/master/arch/x86/kernel/traps.c) 中。在前一部分我们已经看了 `set_intr_gate_ist` 和 `set_system_intr_gate_ist` 的实现，现在我们要看下这两个异常处理程序的实现。from the [arch/x86/kernel/traps.c](https://github.com/torvalds/linux/tree/master/arch/x86/kernel/traps.c). We already saw implementation of the `set_intr_gate_ist` and `set_system_intr_gate_ist` functions in the previous part and now we will look on the implementation of these two exceptions handlers.

调试和断点异常Debug and Breakpoint exceptions
--------------------------------------------------------------------------------

好的，我们在 `early_trap_init` 函数中为 `#DB` 和 `#BP` 设置异常处理程序，现在是时候考虑下它们的实现了。但是在我们这么做之前，首先让我们看下这些异常的细节。Ok, we setup exception handlers in the `early_trap_init` function for the `#DB` and `#BP` exceptions and now time is to consider their implementations. But before we will do this, first of all let's look on details of these exceptions.

第一个异常 - `#DB` 或者 `debug` 异常当调试事件发生时发生。例如 - 试图改变[调试寄存器](http://en.wikipedia.org/wiki/X86_debug_register)内容时。调试寄存器是一种特殊的寄存器，是 `x86` 处理器从 [Intel 80386](http://en.wikipedia.org/wiki/Intel_80386) 开始引入的，并且就像从这个 CPU 扩展的名字你可以理解的，这些寄存器的主要目的就是调试。The first exceptions - `#DB` or `debug` exception occurs when a debug event occurs. For example - attempt to change the contents of a [debug register](http://en.wikipedia.org/wiki/X86_debug_register). Debug registers are special registers that were presented in `x86` processors starting from the [Intel 80386](http://en.wikipedia.org/wiki/Intel_80386) processor and as you can understand from name of this CPU extension, main purpose of these registers is debugging.

这些寄存器允许在代码上设置断点，并且读取或写入数据来跟踪它。调试寄存器必须在特权模式下访问，试图在其它特权级别下读写调试寄存器会导致[通用保护错误](https://en.wikipedia.org/wiki/General_protection_fault)异常。这就是我们为什么为 `#DB` 异常使用 `set_intr_gate_ist`，而不是 `set_system_intr_gate_ist`。These registers allow to set breakpoints on the code and read or write data to trace it. Debug registers may be accessed only in the privileged mode and an attempt to read or write the debug registers when executing at any other privilege level causes a [general protection fault](https://en.wikipedia.org/wiki/General_protection_fault) exception. That's why we have used `set_intr_gate_ist` for the `#DB` exception, but not the `set_system_intr_gate_ist`.

`#DB` 异常的向量号是 `1`（我们将其作为 `X86_TRAP_DB` 传递），我们可以在规范中读到，这个异常没有错误码：The verctor number of the `#DB` exceptions is `1` (we pass it as `X86_TRAP_DB`) and as we may read in specification, this exception has no error code:

```
+-----------------------------------------------------+
|Vector|Mnemonic|Description         |Type |Error Code|
+-----------------------------------------------------+
|1     | #DB    |Reserved            |F/T  |NO        |
+-----------------------------------------------------+
```

第二个异常是 `#BP` 或 `breakpoint` 异常，发生在处理器执行 [int 3](http://en.wikipedia.org/wiki/INT_%28x86_instruction%29#INT_3) 指令时。与 `DB` 异常不同，`#BP` 异常可以发生在用户态。我们可以将其添加到我们的代码中，例如，让我们来看个简单的程序：The second exception is `#BP` or `breakpoint` exception occurs when processor executes the [int 3](http://en.wikipedia.org/wiki/INT_%28x86_instruction%29#INT_3) instruction. Unlike the `DB` exception, the `#BP` exception may occur in userspace. We can add it anywhere in our code, for example let's look on the simple program:

```C
// breakpoint.c
#include <stdio.h>

int main() {
    int i;
    while (i < 6){
	    printf("i equal to: %d\n", i);
	    __asm__("int3");
		++i;
    }
}
```

如果我们编译并运行这个程序，我们会看到如下输出：If we will compile and run this program, we will see following output:

```
$ gcc breakpoint.c -o breakpoint
i equal to: 0
Trace/breakpoint trap
```

但如果在 gdb 中运行这个程序，我们就会看到我们的断点，并可以继续执行我们的程序：But if will run it with gdb, we will see our breakpoint and can continue execution of our program:

```
$ gdb breakpoint
...
...
...
(gdb) run
Starting program: /home/alex/breakpoints 
i equal to: 0

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:	83 45 fc 01	add    DWORD PTR [rbp-0x4],0x1
(gdb) c
Continuing.
i equal to: 1

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:	83 45 fc 01	add    DWORD PTR [rbp-0x4],0x1
(gdb) c
Continuing.
i equal to: 2

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:	83 45 fc 01	add    DWORD PTR [rbp-0x4],0x1
...
...
...
```

从此刻起，我们了解了这两个异常，可以继续分析它们的处理程序了。From this moment we know a little about these two exceptions and we can move on to consideration of their handlers.

异常处理之前的准备Preparation before an exception handler
--------------------------------------------------------------------------------

你之前应该注意到， `set_intr_gate_ist` 和 `set_system_intr_gate_ist` 函数将异常处理程序的地址作为它们的第二个参数。在我们的例子中，两个异常处理程序是：As you may note before, the `set_intr_gate_ist` and `set_system_intr_gate_ist` functions takes an addresses of exceptions handlers in theirs second parameter. In or case our two exception handlers will be:

* `debug`;
* `int3`.

在 C 代码中你找不到这些函数。所有这些函数都可以在内核的 `*.c/*.h` 中找到，这些函数定义在 [arch/x86/include/asm/traps.h](https://github.com/torvalds/linux/tree/master/arch/x86/include/asm/traps.h) 内核头文件中：You will not find these functions in the C code. all of that could be found in the kernel's `*.c/*.h` files only definition of these functions which are located in the [arch/x86/include/asm/traps.h](https://github.com/torvalds/linux/tree/master/arch/x86/include/asm/traps.h) kernel header file:

```C
asmlinkage void debug(void);
```

and

```C
asmlinkage void int3(void);
```

你可能注意到了这些函数定义中的 `asmlinkage` 指令。该指令是 [gcc](http://en.wikipedia.org/wiki/GNU_Compiler_Collection) 的特殊说明符。实际上对于在汇编里调用的 `C` 函数，我们需要明确声明函数调用约定。在我们的例子中，如果函数使用了 `asmlinkage` 描述符，`gcc` 将编译该函数为从栈中取参数。You may note `asmlinkage` directive in definitions of these functions. The directive is the special specificator of the [gcc](http://en.wikipedia.org/wiki/GNU_Compiler_Collection). Actually for a `C` functions which are called from assembly, we need in explicit declaration of the function calling convention. In our case, if function made with `asmlinkage` descriptor, then `gcc` will compile the function to retrieve parameters from stack.

所以，这两个处理函数都是用 `idtentry` 宏定义在 [arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/entry_64.S) 汇编源码文件中：So, both handlers are defined in the [arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/entry_64.S) assembly source code file with the `idtentry` macro:

```assembly
idtentry debug do_debug has_error_code=0 paranoid=1 shift_ist=DEBUG_STACK
```

以及and

```assembly
idtentry int3 do_int3 has_error_code=0 paranoid=1 shift_ist=DEBUG_STACK
```

每个异常处理程序可能由两部分组成。第一部分是通用部分，对于所有异常处理程序都是相同的。一个异常处理程序要在栈上保存[通用寄存器](https://en.wikipedia.org/wiki/Processor_register)，如果异常来自用户态，则切换到内核栈，并将控制权移交给异常处理程序的第二部分。异常处理程序的第二部分做某些工作取决于某些异常。例如，缺页异常应该找到给定地址的虚拟页面，无效操作码异常处理程序应该发送 `SIGILL` [signal](https://en.wikipedia.org/wiki/Unix_signal)，等等。Each exception handler may be consists from two parts. The first part is generic part and it is the same for all exception handlers. An exception handler should to save  [general purpose registers](https://en.wikipedia.org/wiki/Processor_register) on the stack, switch to kernel stack if an exception came from userspace and transfer control to the second part of an exception handler. The second part of an exception handler does certain work depends on certain exception. For example page fault exception handler should find virtual page for given address, invalid opcode exception handler should send `SIGILL` [signal](https://en.wikipedia.org/wiki/Unix_signal) and etc.

正如我们刚看到的，异常处理程序从 [arch/x86/kernel/entry_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/entry_64.S) 汇编源码文件的 `idtentry` 宏定义开始，所以让我们来看下这个宏的实现。如我们所见，`idtentry` 宏有五个参数：As we just saw, an exception handler starts from definition of the `idtentry` macro from the [arch/x86/kernel/entry_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/entry_64.S) assembly source code file, so let's look at implementation of this macro. As we may see, the `idtentry` macro takes five arguments:

* `sym` - 使用 `.globl name` 定义全局符号，它将是异常处理程序的一个条目；defines global symbol with the `.globl name` which will be an an entry of exception handler;
* `do_sym` - 表示异常处理程序辅助条目的符号名；symbol name which represents a secondary entry of an exception handler;
* `has_error_code` - 有关异常错误码存在的信息information about existence of an error code of exception.

最后两个参数是可选的：The last two parameters are optional:

* `paranoid` - 显示我们需要如何检测当前模式（稍后会详细解释）；shows us how we need to check current mode (will see explanation in details later);
* `shift_ist` - 显示异常运行在`中断栈表`。shows us is an exception running at `Interrupt Stack Table`.

`.idtentry` 宏的定义为：Definition of the `.idtentry` macro looks:

```assembly
.macro idtentry sym do_sym has_error_code:req paranoid=0 shift_ist=-1
ENTRY(\sym)
...
...
...
END(\sym)
.endm
```

在我们研究 `idtentry` 宏的本质前，我们应该知道当异常发生时栈的状态。我们可以阅读 [Intel® 64 and IA-32 Architectures Software Developer’s Manual 3A](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)得知，当异常发生时栈的状态如下：Before we will consider internals of the `idtentry` macro, we should to know state of stack when an exception occurs. As we may read in the [Intel® 64 and IA-32 Architectures Software Developer’s Manual 3A](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html), the state of stack when an exception occurs is following:

```
    +------------+
+40 | %SS        |
+32 | %RSP       |
+24 | %RFLAGS    |
+16 | %CS        |
 +8 | %RIP       |
  0 | ERROR CODE | <-- %RSP
    +------------+
```

现在我们可以开始分析 `idt macro` 的实现了。`#DB` 和 `BP` 异常处理都定义为：Now we may start to consider implementation of the `idtmacro`. Both `#DB` and `BP` exception handlers are defined as:

```assembly
idtentry debug do_debug has_error_code=0 paranoid=1 shift_ist=DEBUG_STACK
idtentry int3 do_int3 has_error_code=0 paranoid=1 shift_ist=DEBUG_STACK
```

如果我们看下这些定义，我们就会知道编译将会产生两个名为 `debug` and `int3` 的例程，这两个异常处理程序在一些准备工作之后，将会调用 `do_debug` 和 `do_int3` 辅助处理程序。第三个参数定义了错误码是否存在，我们可看到我们的异常都没有这两个参数。如上图所示，如果异常提供了错误码，处理则将其压栈。在我们的例子中， `debug` 和 `int3` 异常都没有错误码。这可能会带来一些困难，因为对于提供了错误码和没提供错误码的异常，栈看起来就不同了。这是为什么如果一个异常没有提供错误码， `idtentry` 宏的实现会从压一个假的错误码入栈开始：If we will look at these definitions, we may know that compiler will generate two routines with `debug` and `int3` names and both of these exception handlers will call `do_debug` and `do_int3` secondary handlers after some preparation. The third parameter defines existence of error code and as we may see both our exception do not have them. As we may see on the diagram above, processor pushes error code on stack if an exception provides it. In our case, the `debug` and `int3` exception do not have error codes. This may bring some difficulties because stack will look differently for exceptions which provides error code and for exceptions which not. That's why implementation of the `idtentry` macro starts from putting a fake error code to the stack if an exception does not provide it:

```assembly
.ifeq \has_error_code
    pushq	$-1
.endif
```

但它不仅是一个假的错误码。此外， `-1` 也表示无效的系统调用号，使得系统调用重启逻辑不会被触发。But it is not only fake error-code. Moreover the `-1` also represents invalid system call number, so that the system call restart logic will not be triggered.

`idtentry` 宏的最后两个参数 `shift_ist` 和 `paranoid` 使我们知道一个异常处理程序是否从`中断栈表`运行栈。你已经知道系统中的每个内核线程都有自己的栈。除了这些栈外，还有一些与每个处理器相关的专门的栈。这些栈其中之一是 - 异常栈。[x86_64](https://en.wikipedia.org/wiki/X86-64) 架构提供了特殊的特性，称之为`中断栈表`。这个特性允许为制定事件切换到新栈，例如像`双重错误`这样的原子异常等等。因此 `shift_ist` 参数允许我们知道是否需要为一个异常处理函数切换到 `IST` 栈。The last two parameters of the `idtentry` macro `shift_ist` and `paranoid` allow to know do an exception handler runned at stack from `Interrupt Stack Table` or not. You already may know that each kernel thread in the system has own stack. In addition to these stacks, there are some specialized stacks associated with each processor in the system. One of these stacks is - exception stack. The [x86_64](https://en.wikipedia.org/wiki/X86-64) architecture provides special feature which is called - `Interrupt Stack Table`. This feature allows to switch to a new stack for designated events such as an atomic exceptions like `double fault` and etc. So the `shift_ist` parameter allows us to know do we need to switch on `IST` stack for an exception handler or not.

第二个参数 - `paranoid` 定义了有助于我们知道来自用户态还是异常处理程序的方法。确定这一点的最简单的方法是通过 `CS` 段寄存器中的 `CPL`，即`当前特权级别`：如果它等于 `3`，我们来自用户态，如果是 `0`，则是来自内核态：The second parameter - `paranoid` defines the method which helps us to know did we come from userspace or not to an exception handler. The easiest way to determine this is to via `CPL` or `Current Privilege Level` in `CS` segment register. If it is equal to `3`, we came from userspace, if zero we came from kernel space:

```
testl $3,CS(%rsp)
jnz userspace
...
...
...
// we are from the kernel space
```

但不幸的是，这种方法不能给予 100% 的保证。内核文档中这样描述：But unfortunately this method does not give a 100% guarantee. As described in the kernel documentation:

> 如果我们处在一个NMI/MCE/DEBUG/ 任何超原子入口上下文中，if we are in an NMI/MCE/DEBUG/whatever super-atomic entry context,
> 那将会在一个普通项将 CS 写入栈之后which might have triggered right after a normal entry wrote CS to the
> 但是在我们执行 SWAPGS 之前触发，那么检查 GS 唯一安全的方法则是：RDMSR，stack but before we executed SWAPGS, then the only safe way to check
> 这个方法比较慢for GS is the slower method: the RDMSR.

换句话说，比如 `NMI`，可能发生在 [swapgs](http://www.felixcloutier.com/x86/SWAPGS.html) 指令的临界区内。使用这种方法，我们应检查 `MSR_GS_BASE` [MSR 寄存器](https://en.wikipedia.org/wiki/Model-specific_register) 的值，该寄存器保存了指向 per-cpu 区域起始（地址）的指针。因此要检查我们是否来自用户态，我们应该检查 `MSR_GS_BASE` MSR 寄存器的值，如果它为负，我们来自内核态，否则来自用户态：In other words for example `NMI` could happen inside the critical section of a [swapgs](http://www.felixcloutier.com/x86/SWAPGS.html) instruction. In this way we should check value of the `MSR_GS_BASE` [model specific register](https://en.wikipedia.org/wiki/Model-specific_register) which stores pointer to the start of per-cpu area. So to check did we come from userspace or not, we should to check value of the `MSR_GS_BASE` model specific register and if it is negative we came from kernel space, in other way we came from userspace:

```assembly
movl $MSR_GS_BASE,%ecx
rdmsr
testl %edx,%edx
js 1f
```

前两行代码，我们读取 `MSR_GS_BASE` MSR 寄存器的值到 `edx:eax` 对。我们无法为用户态的 `gs` 设置负值。但是另一方面，我们知道物理地址的直接映射从 `0xffff880000000000` 虚拟机地址开始。这样，`MSR_GS_BASE` 将包含从 `0xffff880000000000` 到 `0xffffc7ffffffffff` 的地址。执行 `rdmsr` 指令后，在 `%edx` 寄存器中的最小值可能是 - `0xffff8800`，即无符号 4 字节的 `-30720`。这是为什么内核空间指向 `per-cpu` 区域起始（地址）的 `gs` 会包含负值。In first two lines of code we read value of the `MSR_GS_BASE` model specific register into `edx:eax` pair. We can't set negative value to the `gs` from userspace. But from other side we know that direct mapping of the physical memory starts from the `0xffff880000000000` virtual address. In this way, `MSR_GS_BASE` will contain an address from `0xffff880000000000` to `0xffffc7ffffffffff`. After the `rdmsr` instruction will be executed, the smallest possible value in the `%edx` register will be - `0xffff8800` which is `-30720` in unsigned 4 bytes. That's why kernel space `gs` which points to start of `per-cpu` area will contain negative value.

在我们将错误码压栈后，我们应该为通用寄存器分配空间：After we pushed fake error code on the stack, we should allocate space for general purpose registers with:

```assembly
ALLOC_PT_GPREGS_ON_STACK
```

该宏定义在 [arch/x86/entry/calling.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/calling.h) 头文件中。这个宏只是分配 15*8 字节空间来保存通用寄存器：macro which is defined in the [arch/x86/entry/calling.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/calling.h) header file. This macro just allocates 15*8 bytes space on the stack to preserve general purpose registers:

```assembly
.macro ALLOC_PT_GPREGS_ON_STACK addskip=0
    addq	$-(15*8+\addskip), %rsp
.endm
```

因此，在执行了 `ALLOC_PT_GPREGS_ON_STACK` 之后，栈看起来像这样：So the stack will look like this after execution of the `ALLOC_PT_GPREGS_ON_STACK`:

```
     +------------+
+160 | %SS        |
+152 | %RSP       |
+144 | %RFLAGS    |
+136 | %CS        |
+128 | %RIP       |
+120 | ERROR CODE |
     |------------|
+112 |            |
+104 |            |
 +96 |            |
 +88 |            |
 +80 |            |
 +72 |            |
 +64 |            |
 +56 |            |
 +48 |            |
 +40 |            |
 +32 |            |
 +24 |            |
 +16 |            |
  +8 |            |
  +0 |            | <- %RSP
     +------------+
```

在我们为通用寄存器分配了空间后，我们做一些检查，以了解一个异常是否来自用户态，如果是，我们应该回到被中断程序的栈或者停留在异常栈：After we allocated space for general purpose registers, we do some checks to understand did an exception come from userspace or not and if yes, we should move back to an interrupted process stack or stay on exception stack:

```assembly
.if \paranoid
    .if \paranoid == 1
	    testb	$3, CS(%rsp)
	    jnz	1f
	.endif
	call	paranoid_entry
.else
	call	error_entry
.endif
```

让我们来考虑所有的这些情况。Let's consider all of these there cases in course.

用户空间发生的异常An exception occured in userspace
--------------------------------------------------------------------------------

首先让我们一个有 `paranoid=1` 的异常，例如我们的 `debug` 和 `int3` 异常。在这种情况下，我们检查 `CS` 段寄存器的选择符，如果我们来自用户空间就跳到 `1f` 标签，否则调用 `paranoid_entry`。In the first let's consider a case when an exception has `paranoid=1` like our `debug` and `int3` exceptions. In this case we check selector from `CS` segment register and jump at `1f` label if we came from userspace or the `paranoid_entry` will be called in other way.

让我们考虑下第一种情况，从用户空间到异常处理程序。如上所述，我们应该跳转到 `1` 标签。`1` 标签从调用Let's consider first case when we came from userspace to an exception handler. As described above we should jump at `1` label. The `1` label starts from the call of the

```assembly
call	error_entry
```

例程开始，该例程将所有通用寄存器保存在栈中先前分配的区域中：routine which saves all general purpose registers in the previously allocated area on the stack:

```assembly
SAVE_C_REGS 8
SAVE_EXTRA_REGS 8
```

这两个宏都定义在  [arch/x86/entry/calling.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/calling.h) 头文件中，只是将通用寄存器的值移动到栈中的某个位置，如：These both macros are defined in the  [arch/x86/entry/calling.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/calling.h) header file and just move values of general purpose registers to a certain place at the stack, for example:

```assembly
.macro SAVE_EXTRA_REGS offset=0
	movq %r15, 0*8+\offset(%rsp)
	movq %r14, 1*8+\offset(%rsp)
	movq %r13, 2*8+\offset(%rsp)
	movq %r12, 3*8+\offset(%rsp)
	movq %rbp, 4*8+\offset(%rsp)
	movq %rbx, 5*8+\offset(%rsp)
.endm
```

执行了 `SAVE_C_REGS` 和 `SAVE_EXTRA_REGS` 之后，栈看起来是这样：After execution of `SAVE_C_REGS` and `SAVE_EXTRA_REGS` the stack will look:

```
     +------------+
+160 | %SS        |
+152 | %RSP       |
+144 | %RFLAGS    |
+136 | %CS        |
+128 | %RIP       |
+120 | ERROR CODE |
     |------------|
+112 | %RDI       |
+104 | %RSI       |
 +96 | %RDX       |
 +88 | %RCX       |
 +80 | %RAX       |
 +72 | %R8        |
 +64 | %R9        |
 +56 | %R10       |
 +48 | %R11       |
 +40 | %RBX       |
 +32 | %RBP       |
 +24 | %R12       |
 +16 | %R13       |
  +8 | %R14       |
  +0 | %R15       | <- %RSP
     +------------+
```

内核在栈上保存了通用寄存器后，我们应该再次检查我们是来自用户空间的：After the kernel saved general purpose registers at the stack, we should check that we came from userspace space again with:

```assembly
testb	$3, CS+8(%rsp)
jz	.Lerror_kernelspace
```

因为假如如文档所述截断 `%RIP` 上报，我们就可能会有潜在的错误。无论如何，这两种情况下 [SWAPGS](http://www.felixcloutier.com/x86/SWAPGS.html) 都会执行， `MSR_KERNEL_GS_BASE` 和 `MSR_GS_BASE` 的值会被交换。从此刻起，`%gs` 寄存器将指向内核结构的基址。因此，`SWAPGS` 指令被调用，并且它是 `error_entry` 的主要点。because we may have potentially fault if as described in documentation truncated `%RIP` was reported. Anyway, in both cases the [SWAPGS](http://www.felixcloutier.com/x86/SWAPGS.html) instruction will be executed and values from `MSR_KERNEL_GS_BASE` and `MSR_GS_BASE` will be swapped. From this moment the `%gs` register will point to the base address of kernel structures. So, the `SWAPGS` instruction is called and it was main point of the `error_entry` routing.

现在我们回到 `idtentry` 宏。在 `error_entry` 调用之后，我们可以看到如下汇编代码：Now we can back to the `idtentry` macro. We may see following assembler code after the call of `error_entry`:

```assembly
movq	%rsp, %rdi
call	sync_regs
```

这里我们把栈指针的基地址放入 `%rdi` 寄存器，作为 `sync_regs` 函数的第一个参数（根据 [x86_64 ABI](https://www.uclibc.org/docs/psABI-x86_64.pdf)），并调用定义在源码文件 [arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/traps.c) 中的这个函数：Here we put base address of stack pointer `%rdi` register which will be first argument (according to [x86_64 ABI](https://www.uclibc.org/docs/psABI-x86_64.pdf)) of the `sync_regs` function and call this function which is defined in the [arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/traps.c) source code file:

```C
asmlinkage __visible notrace struct pt_regs *sync_regs(struct pt_regs *eregs)
{
	struct pt_regs *regs = task_pt_regs(current);
	*regs = *eregs;
	return regs;
}
```

这个函数采用了 `task_ptr_regs` 宏的结果，该宏定义在 [arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/processor.h) 头文件中，保存该结果到栈指针，并将其返回。`task_ptr_regs` 宏展开为 `thread.sp0` 的地址，它表示正常内核栈的指针：This function takes the result of the `task_ptr_regs` macro which is defined in the [arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/processor.h) header file, stores it in the stack pointer and return it. The `task_ptr_regs` macro expands to the address of `thread.sp0` which represents pointer to the normal kernel stack:

```C
#define task_pt_regs(tsk)       ((struct pt_regs *)(tsk)->thread.sp0 - 1)
```

因为我们来自用户空间，这意味着异常处理程序将在实际的进程上下文中运行。从 `sync_regs` 中获得栈指针后，我们切换栈：As we came from userspace, this means that exception handler will run in real process context. After we got stack pointer from the `sync_regs` we switch stack:

```assembly
movq	%rax, %rsp
```

异常处理程序之前的最后两步，是调用辅助处理函数：The last two steps before an exception handler will call secondary handler are:

1. 将 `pt_regs` 结构体指针（包含保存的通用寄存器）放入 `%rdi` 寄存器，1. Passing pointer to `pt_regs` structure which contains preserved general purpose registers to the `%rdi` register:

```assembly
movq	%rsp, %rdi
```

因为它将作为辅助异常处理函数的第一个参数。as it will be passed as first parameter of secondary exception handler.

2. 将错误码传给 `%rsi` 寄存器，因为它将作为辅助异常处理函数的第二个参数，并在栈上将其设置为 `-1`，以达到与之前相同的目的 - 防止重新启动系统调用：2. Pass error code to the `%rsi` register as it will be second argument of an exception handler and set it to `-1` on the stack for the same purpose as we did it before - to prevent restart of a system call:

```
.if \has_error_code
	movq	ORIG_RAX(%rsp), %rsi
	movq	$-1, ORIG_RAX(%rsp)
.else
	xorl	%esi, %esi
.endif
```

另外，如果异常不提供错误码，你可以看到在上面的例子中，我们将 `%esi` 寄存器置零。Additionally you may see that we zeroed the `%esi` register above in a case if an exception does not provide error code. 

最后我们只需调用辅助异常处理函数：In the end we just call secondary exception handler:

```assembly
call	\do_sym
```

其中：which:

```C
dotraplinkage void do_debug(struct pt_regs *regs, long error_code);
```

将用于 `debug` 异常：will be for `debug` exception and:

```C
dotraplinkage void notrace do_int3(struct pt_regs *regs, long error_code);
```

将用于 `int 3` 异常。在本部分我们不会看到辅助处理函数的实现，因为它们是非常具体的，我们将在下面的某一部分看到它们。will be for `int 3` exception. In this part we will not see implementations of secondary handlers, because of they are very specific, but will see some of them in one of next parts.

我们只研究了当异常发生在用户空间的第一种情形。让我们来考虑最后两个。We just considered first case when an exception occurred in userspace. Let's consider last two.

发生在内核空间中的 paranoid > 0 的异常An exception with paranoid > 0 occurred in kernelspace
--------------------------------------------------------------------------------

在这种情况下，异常发生在内核空间，`idtentry` 宏被定义为 `paranoid=1`。`paranoid` 的这个值意味着我们应该使用在本部分开始我们看到的较慢的方式，来检查我们是否确认来自内核空间。`paranoid_entry` 例程允许我们知道这点：In this case an exception was occurred in kernelspace and `idtentry` macro is defined with `paranoid=1` for this exception. This value of `paranoid` means that we should use slower way that we saw in the beginning of this part to check do we really came from kernelspace or not. The `paranoid_entry` routing allows us to know this:

```assembly
ENTRY(paranoid_entry)
	cld
	SAVE_C_REGS 8
	SAVE_EXTRA_REGS 8
	movl	$1, %ebx
	movl	$MSR_GS_BASE, %ecx
	rdmsr
	testl	%edx, %edx
	js	1f
	SWAPGS
	xorl	%ebx, %ebx
1:	ret
END(paranoid_entry)
```

如你所见，这个函数表示的和我们之前介绍的相同。我们使用第二种（慢速）方法来获取关于中断任务之前状态的信息。当我们检查这个，并在来自用户空间的情况下执行 `SWAPGS` 时，我们要做的应该和以前一样：我们需要把一个指向通用寄存器的结构指针放入 `%rdi`（辅助处理函数的第一个参数），如果异常提供了错误码，就将其放入 `%rsi`（辅助处理函数的第二个参数）：As you may see, this function represents the same that we covered before. We use second (slow) method to get information about previous state of an interrupted task. As we checked this and executed `SWAPGS` in a case if we came from userspace, we should to do the same that we did before: We need to put pointer to a structure which holds general purpose registers to the `%rdi` (which will be first parameter of a secondary handler) and put error code if an exception provides it to the `%rsi` (which will be second parameter of a secondary handler):

```assembly
movq	%rsp, %rdi

.if \has_error_code
	movq	ORIG_RAX(%rsp), %rsi
	movq	$-1, ORIG_RAX(%rsp)
.else
	xorl	%esi, %esi
.endif
```

调用异常的辅助处理函数之前的最后一步是清理新 `IST` 栈fram：The last step before a secondary handler of an exception will be called is cleanup of new `IST` stack fram:

```assembly
.if \shift_ist != -1
	subq	$EXCEPTION_STKSZ, CPU_TSS_IST(\shift_ist)
.endif
```

你可能还记得我们传递了 `shift_ist` 参数给 `idtentry` 宏。这里我们检查它的值，如果它不等于 `-1`，我们通过 `shift_ist` 索引从`中断栈表`得到指向栈的指针，并设置它。You may remember that we passed the `shift_ist` as argument of the `idtentry` macro. Here we check its value and if its not equal to `-1`, we get pointer to a stack from `Interrupt Stack Table` by `shift_ist` index and setup it.

在第二种方法的最后，像之前一样，我们只是调用辅助异常处理函数：In the end of this second way we just call secondary exception handler as we did it before:

```assembly
call	\do_sym
```

最后一种方法与前面的两种类似，但是在 `paranoid=0` 的情况下发生了异常，我们可以使用快速方法确定我们来自哪儿。The last method is similar to previous both, but an exception occured with `paranoid=0` and we may use fast method determination of where we are from.

从异常处理中退出Exit from an exception handler
--------------------------------------------------------------------------------

辅助处理程序完成其工作以后，我们会返回到 `idtentry` 宏，下一步将是跳转到 `error_exit`例程：After secondary handler will finish its works, we will return to the `idtentry` macro and the next step will be jump to the `error_exit`:

```assembly
jmp	error_exit
```

`error_exit` 函数定义在相同的 [arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/entry_64.S) 汇编源文件中，其主要目的是知道我们来自哪儿（用户空间或内核空间），并执行依赖于此的 `SWPAGS`。恢复寄存器到之前的状态，并执行 `iret` 指令将控制权交给中断任务。routine. The `error_exit` function defined in the same [arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/entry_64.S) assembly source code file and the main goal of this function is to know where we are from (from userspace or kernelspace) and execute `SWPAGS` depends on this. Restore registers to previous state and execute `iret` instruction to transfer control to an interrupted task.

就这么多了。That's all.

Conclusion
--------------------------------------------------------------------------------

这是有关 Linux 内核中断和中断处理第三部分的结尾了。在前面的部分我们用 `#DB` 和 `#BP` 门看了[中断描述符表](https://en.wikipedia.org/wiki/Interrupt_descriptor_table) 的初始化，并开始研究了在控制权转交给异常处理程序之前的准备工作，已经本部分的一些异常处理程序。在下一部分中，我们将继续深入探讨这一主题，接下来是 `setup_arch` 函数，并尝试理解中断处理相关内容。It is the end of the third part about interrupts and interrupt handling in the Linux kernel. We saw the initialization of the [Interrupt descriptor table](https://en.wikipedia.org/wiki/Interrupt_descriptor_table) in the previous part with the `#DB` and `#BP` gates and started to dive into preparation before control will be transferred to an exception handler and implementation of some interrupt handlers in this part. In the next part we will continue to dive into this theme and will go next by the `setup_arch` function and will try to understand interrupts handling related stuff.

If you have any questions or suggestions write me a comment or ping me at [twitter](https://twitter.com/0xAX).

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-insides).**

链接Links
--------------------------------------------------------------------------------

* [Debug registers](http://en.wikipedia.org/wiki/X86_debug_register)
* [Intel 80385](http://en.wikipedia.org/wiki/Intel_80386)
* [INT 3](http://en.wikipedia.org/wiki/INT_%28x86_instruction%29#INT_3)
* [gcc](http://en.wikipedia.org/wiki/GNU_Compiler_Collection)
* [TSS](http://en.wikipedia.org/wiki/Task_state_segment)
* [GNU assembly .error directive](https://sourceware.org/binutils/docs/as/Error.html#Error)
* [dwarf2](http://en.wikipedia.org/wiki/DWARF)
* [CFI directives](https://sourceware.org/binutils/docs/as/CFI-directives.html)
* [IRQ](http://en.wikipedia.org/wiki/Interrupt_request_%28PC_architecture%29)
* [system call](http://en.wikipedia.org/wiki/System_call)
* [swapgs](http://www.felixcloutier.com/x86/SWAPGS.html)
* [SIGTRAP](https://en.wikipedia.org/wiki/Unix_signal#SIGTRAP)
* [Per-CPU variables](http://0xax.gitbooks.io/linux-insides/content/Concepts/per-cpu.html)
* [kgdb](https://en.wikipedia.org/wiki/KGDB)
* [ACPI](https://en.wikipedia.org/wiki/Advanced_Configuration_and_Power_Interface)
* [Previous part](http://0xax.gitbooks.io/linux-insides/content/interrupts/index.html)
