中断和中段处理 Part 2.Interrupts and Interrupt Handling. Part 2.
================================================================================

开始深入 Linux 内核中的中断和异常处理Start to dive into interrupt and exceptions handling in the Linux kernel
--------------------------------------------------------------------------------

我们在上一[部分](http://0xax.gitbooks.io/linux-insides/content/Interrupts/interrupts-1.html)看到了一些中断和异常处理的理论，正如我在那部分写的，我们将在这部分开始深入分析 Linux 源码中的中断和异常。你可能已经注意到了，上一部分主要描述了理论方面，这部分我们将开始直接深入分析 Linux 内核源码。像其它章节一样，我们将从初始的地方开始。我们不会从 Linux 内核源码最开始的[代码行](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/header.S#L292)开始看，比如 [内核引导过程](http://0xax.gitbooks.io/linux-insides/content/Booting/index.html) 章节，我们会从与中断和异常最早的代码开始。在这部分中，我们将涉及 Linux 内核源码中所有与中断和异常有关的东西。We saw some theory about interrupts and exception handling in the previous [part](http://0xax.gitbooks.io/linux-insides/content/Interrupts/interrupts-1.html) and as I already wrote in that part, we will start to dive into interrupts and exceptions in the Linux kernel source code in this part. As you already can note, the previous part mostly described theoretical aspects and in this part we will start to dive directly into the Linux kernel source code. We will start to do it as we did it in other chapters, from the very early places. We will not see the Linux kernel source code from the earliest [code lines](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/header.S#L292) as we saw it for example in the [Linux kernel booting process](http://0xax.gitbooks.io/linux-insides/content/Booting/index.html) chapter, but we will start from the earliest code which is related to the interrupts and exceptions. In this part we will try to go through the all interrupts and exceptions related stuff which we can find in the Linux kernel source code.

如果读过之前的部分，你应该记得和中断相关的 `x86_64` 架构特定 Linux 内核源码最早的位置是在 [arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/pm.c) 源码文件，那代表了[中断描述符表](http://en.wikipedia.org/wiki/Interrupt_descriptor_table)的第一个设置。那发生在 `go_to_protected_mode` 函数中调用 `setup_idt` 转换到保护模式之前：If you've read the previous parts, you can remember that the earliest place in the Linux kernel `x86_64` architecture-specific source code which is related to the interrupt is located in the [arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/pm.c) source code file and represents the first setup of the [Interrupt Descriptor Table](http://en.wikipedia.org/wiki/Interrupt_descriptor_table). It occurs right before the transition into the [protected mode](http://en.wikipedia.org/wiki/Protected_mode) in the `go_to_protected_mode` function by the call of the `setup_idt`:

```C
void go_to_protected_mode(void)
{
	...
	setup_idt();
	...
}
```

`setup_idt` 函数和 `go_to_protected_mode` 函数定义在同一个源码文件中，且只载入了 `NULL` 中断描述符表的地址：The `setup_idt` function is defined in the same source code file as the `go_to_protected_mode` function and just loads the address of the `NULL` interrupts descriptor table:

```C
static void setup_idt(void)
{
	static const struct gdt_ptr null_idt = {0, 0};
	asm volatile("lidtl %0" : : "m" (null_idt));
}
```

其中 `gdt_ptr` 表示一个特殊的48位 `GDTR` 寄存器，它须包含`全局描述符表`的基地址：where `gdt_ptr` represents a special 48-bit `GDTR` register which must contain the base address of the `Global Descriptor Table`:

```C
struct gdt_ptr {
	u16 len;
	u32 ptr;
} __attribute__((packed));
```

当然，在我们的例子中，代表 `GDTR` 寄存器的不是 `gdt_ptr`，而是 `IDTR`，因为我们已经设置了`中断描述符表`。你找不到 `idt_ptr` 结构的，因为如果 Linux 内核定义了它，就和 `gdt_ptr` 是一样的，只是名字不同。所以，你可以理解为这是不合理的：两个结构体类似，只是名字不同。这里你可以注意到，我们没有填充`中断描述符表`的项，因为现在处理任何中断或异常还为时过早。这是为什么我们用 `NULL` 来填充 `IDT`。Of course in our case the `gdt_ptr` does not represent the `GDTR` register, but `IDTR` since we set `Interrupt Descriptor Table`. You will not find an `idt_ptr` structure, because if it had been in the Linux kernel source code, it would have been the same as `gdt_ptr` but with different name. So, as you can understand there is no sense to have two similar structures which differ only by name. You can note here, that we do not fill the `Interrupt Descriptor Table` with entries, because it is too early to handle any interrupts or exceptions at this point. That's why we just fill the `IDT` with `NULL`.

在设置了[中段描述符表](http://en.wikipedia.org/wiki/Interrupt_descriptor_table)、[全局描述符表](http://en.wikipedia.org/wiki/GDT)和其它一些东西后，我们跳到[保护模式](http://en.wikipedia.org/wiki/Protected_mode)（[arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/pmjump.S)）。你可以在描述转换到保护模式的[部分](http://0xax.gitbooks.io/linux-insides/content/Booting/linux-bootstrap-3.html)中阅读到更多信息。After the setup of the [Interrupt descriptor table](http://en.wikipedia.org/wiki/Interrupt_descriptor_table), [Global Descriptor Table](http://en.wikipedia.org/wiki/GDT) and other stuff we jump into [protected mode](http://en.wikipedia.org/wiki/Protected_mode) in the - [arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/master/arch/x86/boot/pmjump.S). You can read more about it in the [part](http://0xax.gitbooks.io/linux-insides/content/Booting/linux-bootstrap-3.html) which describes the transition to protected mode.

从（本书）最早的部分我们已经知道，保护模式的入口在 `boot_params.hdr.code32_start`，并且在 [arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/pm.c) 的末尾你可以看到，我们将保护模式的入口和 `boot_params` 传递给 `protected_mode_jump`。We already know from the earliest parts that entry to protected mode is located in the `boot_params.hdr.code32_start` and you can see that we pass the entry of the protected mode and `boot_params` to the `protected_mode_jump` in the end of the [arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/pm.c):

```C
protected_mode_jump(boot_params.hdr.code32_start,
			    (u32)&boot_params + (ds() << 4));
```

`protected_mode_jump` 定义在 [arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/pmjump.S) 中，且使用一个 [8086](http://en.wikipedia.org/wiki/Intel_8086) [调用约定](http://en.wikipedia.org/wiki/X86_calling_conventions#List_of_x86_calling_conventions)从 `ax` 和 `dx` 中得到两个参数。The `protected_mode_jump` is defined in the [arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/pmjump.S) and gets these two parameters in the `ax` and `dx` registers using one of the [8086](http://en.wikipedia.org/wiki/Intel_8086) calling  [conventions](http://en.wikipedia.org/wiki/X86_calling_conventions#List_of_x86_calling_conventions):

```assembly
GLOBAL(protected_mode_jump)
	...
	...
	...
	.byte	0x66, 0xea		# ljmpl opcode
2:	.long	in_pm32			# offset
	.word	__BOOT_CS		# segment
...
...
...
ENDPROC(protected_mode_jump)
```

其中 `in_pm32` 包含了一个到 32 位入口的跳转：where `in_pm32` contains a jump to the 32-bit entry point:

```assembly
GLOBAL(in_pm32)
	...
	...
	jmpl	*%eax // %eax contains address of the `startup_32`
	...
	...
ENDPROC(in_pm32)
```

你应该记得，这个 32 位的入口点是在 [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/master/arch/x86/boot/compressed/head_64.S) 汇编文件，尽管它的名字里面有一个 `_64`。在 `arch/x86/boot/compressed` 目录中我们可以看到两个类似的文件：As you can remember the 32-bit entry point is in the [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/master/arch/x86/boot/compressed/head_64.S) assembly file, although it contains `_64` in its name. We can see the two similar files in the `arch/x86/boot/compressed` directory:

* `arch/x86/boot/compressed/head_32.S`.
* `arch/x86/boot/compressed/head_64.S`;

但是在我们的情况中 32 位模式的入口点是第二个文件。第一个文件甚至没有编译为 `x86_64`。让我们来看看 [arch/x86/boot/compressed/Makefile](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/compressed/Makefile)：But the 32-bit mode entry point is the second file in our case. The first file is not even compiled for `x86_64`. Let's look at the [arch/x86/boot/compressed/Makefile](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/compressed/Makefile):

```
vmlinux-objs-y := $(obj)/vmlinux.lds $(obj)/head_$(BITS).o $(obj)/misc.o \
...
...
```

在这儿我们可以看到依赖于 `$(BITS)` 变量的 `head_*`，而`$(BITS)` 变量取决于架构。你可以在 [arch/x86/Makefile](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/Makefile) 中找到它：We can see here that `head_*` depends on the `$(BITS)` variable which depends on the architecture. You can find it in the [arch/x86/Makefile](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/Makefile):

```
ifeq ($(CONFIG_X86_32),y)
...
	BITS := 32
else
	BITS := 64
	...
endif
```

现在我们跳到 [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/compressed/head_64.S) 中的 `startup_32`，会发现没有任何和中断处理有关的内容。`startup_32` 包含了转换到[长模式](http://en.wikipedia.org/wiki/Long_mode)前的准备代码，并跳转到长模式（long mode）。`long mode` 入口位于 `startup_64`，它为发生在 [arch/x86/boot/compressed/misc.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/compressed/misc.c) `decompress_kernel` 中的 [内核解压缩](http://0xax.gitbooks.io/linux-insides/content/Booting/linux-bootstrap-5.html)做准备。内核解压后，我们从 [arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/head_64.S) 跳转到 `startup_64`。在 `startup_64` 中，我们开始构建 identity-mapped 页。构建完 identity-mapped 页之后，我们检查 [NX](http://en.wikipedia.org/wiki/NX_bit) 位，设置 `Extended Feature Enable Register` （见链接），用 `lgdt` 指令更新 `全局描述符表`，我们需要用如下代码更新 `gs` 寄存器：Now as we jumped on the `startup_32` from the [arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/compressed/head_64.S) we will not find anything related to the interrupt handling here. The `startup_32` contains code that makes preparations before the transition into [long mode](http://en.wikipedia.org/wiki/Long_mode) and directly jumps in to it. The `long mode` entry is located in `startup_64` and it makes preparations before the [kernel decompression](http://0xax.gitbooks.io/linux-insides/content/Booting/linux-bootstrap-5.html) that occurs in the `decompress_kernel` from the [arch/x86/boot/compressed/misc.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/boot/compressed/misc.c). After the kernel is decompressed, we jump on the `startup_64` from the [arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/head_64.S). In the `startup_64` we start to build identity-mapped pages. After we have built identity-mapped pages, checked the [NX](http://en.wikipedia.org/wiki/NX_bit) bit, setup the `Extended Feature Enable Register` (see in links), and updated the early `Global Descriptor Table` with the `lgdt` instruction, we need to setup `gs` register with the following code:

```assembly
movl	$MSR_GS_BASE,%ecx
movl	initial_gs(%rip),%eax
movl	initial_gs+4(%rip),%edx
wrmsr
```

我们已经在上一[部分](http://0xax.gitbooks.io/linux-insides/content/interrupts/interrupts-1.html)看了这部分代码。首先注意最后的 `wrmsr` 指令。这个指令将数据从 `edx:eax` 寄存器写入 `ecx` 指定的 [model specific register](http://en.wikipedia.org/wiki/Model-specific_register)。我们可以看到 `ecx` 包含了 `$MSR_GS_BASE`，它定义在 [arch/x86/include/uapi/asm/msr-index.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/uapi/asm/msr-index.h)，如下所示：We already saw this code in the previous [part](http://0xax.gitbooks.io/linux-insides/content/interrupts/interrupts-1.html). First of all pay attention on the last `wrmsr` instruction. This instruction writes data from the `edx:eax` registers to the [model specific register](http://en.wikipedia.org/wiki/Model-specific_register) specified by the `ecx` register. We can see that `ecx` contains `$MSR_GS_BASE` which is declared in the [arch/x86/include/uapi/asm/msr-index.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/uapi/asm/msr-index.h) and looks like:

```C
#define MSR_GS_BASE             0xc0000101
```

从这儿我们可以理解到，`MSR_GS_BASE` 定义了 `MSR` 寄存器的标号。由于在 64 位模式下不再使用 `cs`, `ds`, `es` 和 `ss` 寄存器，它们的字段会被忽略。但是我们可以通过 `fs` 和 `gs` 寄存器访问内存。`MSR` 寄存器为这些段寄存器的隐藏部分提供了`后门`，并允许使用 64 位基地址来通过 `fs` 和 `gs` 寻址段寄存器。所以 `MSR_GS_BASE` 是隐藏的部分，这部分映射为 `GS.base` 字段。让我们来看下 `initial_gs`：From this we can understand that `MSR_GS_BASE` defines the number of the `model specific register`. Since registers `cs`, `ds`, `es`, and `ss` are not used in the 64-bit mode, their fields are ignored. But we can access memory over `fs` and `gs` registers. The model specific register provides a `back door` to the hidden parts of these segment registers and allows to use 64-bit base address for segment register addressed by the `fs` and `gs`. So the `MSR_GS_BASE` is the hidden part and this part is mapped on the `GS.base` field. Let's look on the `initial_gs`:

```assembly
GLOBAL(initial_gs)
	.quad	INIT_PER_CPU_VAR(irq_stack_union)
```

我们将 `irq_stack_union` 符号传递给 `INIT_PER_CPU_VAR` 宏，改宏只是将 `init_per_cpu__` 前缀与给定符号连接起来。在我们的例子中，我们得到 `init_per_cpu__irq_stack_union` 符号。让我们来看下[链接器](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/vmlinux.lds.S)脚本。我们可以看到以下定义：We pass `irq_stack_union` symbol to the `INIT_PER_CPU_VAR` macro which just concatenates the `init_per_cpu__` prefix with the given symbol. In our case we will get the `init_per_cpu__irq_stack_union` symbol. Let's look at the [linker](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/vmlinux.lds.S) script. There we can see following definition:

```
#define INIT_PER_CPU(x) init_per_cpu__##x = x + __per_cpu_load
INIT_PER_CPU(irq_stack_union);
```

它告诉我们， `init_per_cpu__irq_stack_union` 将是 `irq_stack_union + __per_cpu_load`。现在我们需要理解 `init_per_cpu__irq_stack_union` 和 `__per_cpu_load` 是什么意思。第一个 `irq_stack_union` 在 [arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/processor.h) 中以 `DECLARE_INIT_PER_CPU` 宏进行定义，后者扩展为 `init_per_cpu_var` 宏：It tells us that the address of the `init_per_cpu__irq_stack_union` will be `irq_stack_union + __per_cpu_load`. Now we need to understand where `init_per_cpu__irq_stack_union` and `__per_cpu_load` are what they mean. The first `irq_stack_union` is defined in the [arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/processor.h) with the `DECLARE_INIT_PER_CPU` macro which expands to call the `init_per_cpu_var` macro:

```C
DECLARE_INIT_PER_CPU(irq_stack_union);

#define DECLARE_INIT_PER_CPU(var) \
       extern typeof(per_cpu_var(var)) init_per_cpu_var(var)

#define init_per_cpu_var(var)  init_per_cpu__##var
```

如果我们扩展所有的宏，我们将得到和扩展 `INIT_PER_CPU` 宏相同的 `init_per_cpu__irq_stack_union`。你可以注意到，它不仅仅是一个符号，还是一个变量。让我们来看下 `typeof(per_cpu_var(var))` 表达式。我们的 `var` 是 `irq_stack_union`，并且 `per_cpu_var` 定义在 [arch/x86/include/asm/percpu.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/percpu.h)：If we expand all macros we will get the same `init_per_cpu__irq_stack_union` as we got after expanding the `INIT_PER_CPU` macro, but you can note that it is not just a symbol, but a variable. Let's look at the `typeof(per_cpu_var(var))` expression. Our `var` is `irq_stack_union` and the `per_cpu_var` macro is defined in the [arch/x86/include/asm/percpu.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/percpu.h):

```C
#define PER_CPU_VAR(var)        %__percpu_seg:var
```

其中：where:

```C
#ifdef CONFIG_X86_64
    #define __percpu_seg gs
endif
```

所以，我们正在访问 `gs:irq_stack_union`，并且获取它的类型为 `irq_union`。好，我们定义了第一个变量并知道了它的地址，心在让我们来看下第二个 `__per_cpu_load` 符号。这个符号后面有几个 `per-cpu` 变量。`__per_cpu_load` 定义在 [include/asm-generic/sections.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/asm-generic-sections.h)：So, we are accessing `gs:irq_stack_union` and getting its type which is `irq_union`. Ok, we defined the first variable and know its address, now let's look at the second `__per_cpu_load` symbol. There are a couple of `per-cpu` variables which are located after this symbol. The `__per_cpu_load` is defined in the [include/asm-generic/sections.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/asm-generic-sections.h):

```C
extern char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];
```

它还从数据区提供了 `per-cpu` 变量的基地址。因此，我们知道了 `irq_stack_union` 的基地址、`__per_cpu_load`，还知道了 `init_per_cpu__irq_stack_union` 必须放在 `__per_cpu_load` 后面。我们可以在 [System.map](http://en.wikipedia.org/wiki/System.map) 中看到它：and presented base address of the `per-cpu` variables from the data area. So, we know the address of the `irq_stack_union`, `__per_cpu_load` and we know that `init_per_cpu__irq_stack_union` must be placed right after `__per_cpu_load`. And we can see it in the [System.map](http://en.wikipedia.org/wiki/System.map):

```
...
...
...
ffffffff819ed000 D __init_begin
ffffffff819ed000 D __per_cpu_load
ffffffff819ed000 A init_per_cpu__irq_stack_union
...
...
...
```

现在我们知道了 `initial_gs`，让我们来看看代码：Now we know about `initial_gs`, so let's look at the code:

```assembly
movl	$MSR_GS_BASE,%ecx
movl	initial_gs(%rip),%eax
movl	initial_gs+4(%rip),%edx
wrmsr
```

这里我们用 `MSR_GS_BASE` 指定了 `MSR` 寄存器，将 `initial_gs` 的 64 位地址写入 `edx:eax` 对，并执行 `wrmsr` 指令，来用 `init_per_cpu__irq_stack_union` 的基地址（这将是中断栈的底部）来填充 `gs` 寄存器。之后，我们将从 [arch/x86/kernel/head64.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/head64.c) 跳到 `x86_64_start_kernel` 中的 C 代码。在 `x86_64_start_kernel` 函数中，我们做进入通用和独立架构的内核代码前最后的准备工作，其中一项就是用中断处理程序条目或 `early_idt_handlers` 填充早期的`中断描述符表`。你可以记住它，如果你已经阅读了关于[早期中断和异常处理](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-2.html)的部分，并且可以记住下面的代码：Here we specified a model specific register with `MSR_GS_BASE`, put the 64-bit address of the `initial_gs` to the `edx:eax` pair and execute the `wrmsr` instruction for filling the `gs` register with the base address of the `init_per_cpu__irq_stack_union` which will be at the bottom of the interrupt stack. After this we will jump to the C code on the `x86_64_start_kernel` from the [arch/x86/kernel/head64.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/head64.c). In the `x86_64_start_kernel` function we do the last preparations before we jump into the generic and architecture-independent kernel code and one of these preparations is filling the early `Interrupt Descriptor Table` with the interrupts handlers entries or `early_idt_handlers`. You can remember it, if you have read the part about the [Early interrupt and exception handling](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-2.html) and can remember following code:

```C
for (i = 0; i < NUM_EXCEPTION_VECTORS; i++)
	set_intr_gate(i, early_idt_handlers[i]);

load_idt((const struct desc_ptr *)&idt_descr);
```

但是当我写`早期中断和异常处理`时，Linux 内核版本为 - `3.18`。现在 Linux 内核实际版本是 `4.1.0-rc6+`，并且 ` Andy Lutomirski` 发送了[补丁](https://lkml.org/lkml/2015/6/2/106)，这个补丁修改了 `early_idt_handlers` 的行为，并很快就会进入内核主线。**注意**，当我写本部分时，[补丁](https://github.com/torvalds/linux/commit/425be5679fd292a3c36cb1fe423086708a99f11a)已经进入 Linux 内核源码。让我们来分析下它。现在同一部分看起来像这样：but I wrote `Early interrupt and exception handling` part when Linux kernel version was - `3.18`. For this day actual version of the Linux kernel is `4.1.0-rc6+` and ` Andy Lutomirski` sent the [patch](https://lkml.org/lkml/2015/6/2/106) and soon it will be in the mainline kernel that changes behaviour for the `early_idt_handlers`. **NOTE** While I wrote this part the [patch](https://github.com/torvalds/linux/commit/425be5679fd292a3c36cb1fe423086708a99f11a) already turned in the Linux kernel source code. Let's look on it. Now the same part looks like:

```C
for (i = 0; i < NUM_EXCEPTION_VECTORS; i++)
	set_intr_gate(i, early_idt_handler_array[i]);

load_idt((const struct desc_ptr *)&idt_descr);
```

正如你看到的一样，中断处理函数入口点数组的名字只有一处区别。现在是 `early_idt_handler_arry`：AS you can see it has only one difference in the name of the array of the interrupts handlers entry points. Now it is `early_idt_handler_arry`:

```C
extern const char early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE];
```

其中 `NUM_EXCEPTION_VECTORS` 和 `EARLY_IDT_HANDLER_SIZE` 定义为：where `NUM_EXCEPTION_VECTORS` and `EARLY_IDT_HANDLER_SIZE` are defined as:

```C
#define NUM_EXCEPTION_VECTORS 32
#define EARLY_IDT_HANDLER_SIZE 9
```

因此，是一个中断处理函数入口点的数组，每 9 个字节包含一个入口点。你应该记得先前的 `early_idt_handlers` 定义在 [arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/head_64.S) 中，`early_idt_handler_array` 定义在同一个源码文件中：So, the `early_idt_handler_array` is an array of the interrupts handlers entry points and contains one entry point on every nine bytes. You can remember that previous `early_idt_handlers` was defined in the [arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/head_64.S). The `early_idt_handler_array` is defined in the same source code file too:  

```assembly
ENTRY(early_idt_handler_array)
...
...
...
ENDPROC(early_idt_handler_common)
```

它用 `.rept NUM_EXCEPTION_VECTORS` 填充 `early_idt_handler_arry`，并且包含了 `early_make_pgtable` 中断处理程序项（更多实现内容你可以阅读 [早期中断和异常处理](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-2.html)部分）。现在我们来到了 `x86_64` 特定结构代码的尾声，下一部分是通用的内核代码。当然，你已经知道了我们要返回到 `setup_arch` 函数和其它地方架构特定的代码，但这就是 `x86_64` 早期代码的结尾了。It fills `early_idt_handler_arry` with the `.rept NUM_EXCEPTION_VECTORS` and contains entry of the `early_make_pgtable` interrupt handler (more about its implementation you can read in the part about [Early interrupt and exception handling](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-2.html)). For now we come to the end of the `x86_64` architecture-specific code and the next part is the generic kernel code. Of course you already can know that we will return to the architecture-specific code in the `setup_arch` function and other places, but this is the end of the `x86_64` early code.

为中断堆栈设置堆栈 Canary Setting stack canary for the interrupt stack
-------------------------------------------------------------------------------

[arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/head_64.S) 后的下一站是 [init/main.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/init/main.c) 中最大的函数 `start_kernel`。如果你已经阅读了关于 Linux 内核初始化过程的[上一章](http://0xax.gitbooks.io/linux-insides/content/Initialization/index.html)，你一定记得它。这个函数执行了在第一个 `init` 进程（[pid](https://en.wikipedia.org/wiki/Process_identifier) - `1`）之前的所有初始化内容。与中断和异常处理相关的第一件事是 `boot_init_stack_canary` 函数。The next stop after the [arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/head_64.S) is the biggest `start_kernel` function from the [init/main.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/init/main.c). If you've read the previous [chapter](http://0xax.gitbooks.io/linux-insides/content/Initialization/index.html) about the Linux kernel initialization process, you must remember it. This function does all initialization stuff before kernel will launch first `init` process with the [pid](https://en.wikipedia.org/wiki/Process_identifier) - `1`. The first thing that is related to the interrupts and exceptions handling is the call of the `boot_init_stack_canary` function.

这个函数设置[canary](http://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries) 值以保护中断堆栈溢出。在上一部分我们已经看到了 `boot_init_stack_canary` 实现的一点细节，现在让我们来仔细分析一下。你可以在 [arch/x86/include/asm/stackprotector.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/stackprotector.h) 中找到这个函数的实现，该函数依赖于 `CONFIG_CC_STACKPROTECTOR` 内核配置选项。如果这个选项没配置，这个函数不做任何事：This function sets the [canary](http://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries) value to protect interrupt stack overflow. We already saw a little some details about implementation of the `boot_init_stack_canary` in the previous part and now let's take a closer look on it. You can find implementation of this function in the [arch/x86/include/asm/stackprotector.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/stackprotector.h) and its depends on the `CONFIG_CC_STACKPROTECTOR` kernel configuration option. If this option is not set this function will not do anything:

```C
#ifdef CONFIG_CC_STACKPROTECTOR
...
...
...
#else
static inline void boot_init_stack_canary(void)
{
}
#endif
```

如果设置了 `CONFIG_CC_STACKPROTECTOR` 内核配置选项，`boot_init_stack_canary` 函数首先检查表示 [per-cpu](http://0xax.gitbooks.io/linux-insides/content/Concepts/per-cpu.html) 中断堆栈的 `irq_stack_union` 和 `stack_canary` 值是否是 40 字节的偏移：If the `CONFIG_CC_STACKPROTECTOR` kernel configuration option is set, the `boot_init_stack_canary` function starts from the check stat `irq_stack_union` that represents [per-cpu](http://0xax.gitbooks.io/linux-insides/content/Concepts/per-cpu.html) interrupt stack has offset equal to forty bytes from the `stack_canary` value:

```C
#ifdef CONFIG_X86_64
        BUILD_BUG_ON(offsetof(union irq_stack_union, stack_canary) != 40);
#endif
```

如同我们前面[部分](http://0xax.gitbooks.io/linux-insides/content/interrupts/interrupts-1.html)所阅读到的，`irq_stack_union` 由下述联合表示：As we can read in the previous [part](http://0xax.gitbooks.io/linux-insides/content/interrupts/interrupts-1.html) the `irq_stack_union` represented by the following union:

```C
union irq_stack_union {
	char irq_stack[IRQ_STACK_SIZE];

    struct {
		char gs_base[40];
		unsigned long stack_canary;
	};
};
```

它在 [arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/processor.h) 中定义。我们知道，[C](http://en.wikipedia.org/wiki/C_%28programming_language%29) 编程语言中 [union](http://en.wikipedia.org/wiki/Union_type) 是一种在内存中只存储一个字段的数据结构。我们看到，在该结构体中第一个字段 - `gs_base` 为 40 字节大小，并表示 `irq_stack` 的底。因此，此后我们用 `BUILD_BUG_ON` 宏检测应该成功结束。（如果你对 `BUILD_BUG_ON` 宏感兴趣，可以阅读关于 Linux 内核初始化[过程](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-1.html)的第一部分。）which defined in the [arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/processor.h). We know that [union](http://en.wikipedia.org/wiki/Union_type) in the [C](http://en.wikipedia.org/wiki/C_%28programming_language%29) programming language is a data structure which stores only one field in a memory. We can see here that structure has first fieldwhich is 40 bytes size and represents bottom of the `irq_stack`. So, after this our check with themacro should end successfully. (you can read the first part about Linux kernel initialization [process](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-1.html) if you're interesting about themacro).

随后，我们根据随机数和[时间戳计数器](http://en.wikipedia.org/wiki/Time_Stamp_Counter)计算新的 `canary` 值：After this we calculate new `canary` value based on the random number and [Time Stamp Counter](http://en.wikipedia.org/wiki/Time_Stamp_Counter):

```C
get_random_bytes(&canary, sizeof(canary));
tsc = __native_read_tsc();
canary += tsc + (tsc << 32UL);
```

并使用 `this_cpu_write` 宏将 `canary` 值写入 `irq_stack_union`：and write `canary` value to the `irq_stack_union` with the `this_cpu_write` macro:

```C
this_cpu_write(irq_stack_union.stack_canary, canary);
```

更多关于 `this_cpu_*` 操作你可以阅读[Linux 内核文档](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/Documentation/this_cpu_ops.txt)。more about `this_cpu_*` operation you can read in the [Linux kernel documentation](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/Documentation/this_cpu_ops.txt).

禁用/启用本地中断Disabling/Enabling local interrupts
--------------------------------------------------------------------------------

在 [init/main.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/init/main.c) 中，在将 `canary` 值设置为中断堆栈后，与中断和中断处理相关的下一个步骤，The next step in the [init/main.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/init/main.c) which is related to the interrupts and interrupts handling after we have set the `canary` value to the interrupt stack - is the call of the `local_irq_disable` macro.

这个宏定义在 [include/linux/irqflags.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/irqflags.h) 头文件中，并且就像你理解的，我们可以调用这个宏禁用 CPU 的中断。让我们来看下它的实现。首先要注意，它依赖于内核配置项 `CONFIG_TRACE_IRQFLAGS_SUPPORT`：This macro defined in the [include/linux/irqflags.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/irqflags.h) header file and as you can understand, we can disable interrupts for the CPU with the call of this macro. Let's look on its implementation. First of all note that it depends on the `CONFIG_TRACE_IRQFLAGS_SUPPORT` kernel configuration option:

```C
#ifdef CONFIG_TRACE_IRQFLAGS_SUPPORT
...
#define local_irq_disable() \
         do { raw_local_irq_disable(); trace_hardirqs_off(); } while (0)
...
#else
...
#define local_irq_disable()     do { raw_local_irq_disable(); } while (0)
...
#endif
```

它们是相似的，如你所见，仅有一处区别：当 `CONFIG_TRACE_IRQFLAGS_SUPPORT` 使能时，`local_irq_disable` 宏包含 `trace_hardirqs_off` 的调用。在  [lockdep](http://lwn.net/Articles/321663/) 子系统中有特别的功能 - `irq-flags tracing` 用于跟踪 `hardirq` 和 `softirq` 状态。在我们的例子中，`lockdep` 子系统可以给我们关于发生在系统中的硬/中断开/关事件的有趣信息。`trace_hardirqs_off` 函数定义在 [kernel/locking/lockdep.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/locking/lockdep.c) 中：They are both similar and as you can see have only one difference: the `local_irq_disable` macro contains call of the `trace_hardirqs_off` when `CONFIG_TRACE_IRQFLAGS_SUPPORT` is enabled. There is special feature in the [lockdep](http://lwn.net/Articles/321663/) subsystem - `irq-flags tracing` for tracing `hardirq` and `softirq` state. In our case `lockdep` subsystem can give us interesting information about hard/soft irqs on/off events which are occurs in the system. The `trace_hardirqs_off` function defined in the [kernel/locking/lockdep.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/locking/lockdep.c):

```C
void trace_hardirqs_off(void)
{
         trace_hardirqs_off_caller(CALLER_ADDR0);
}
EXPORT_SYMBOL(trace_hardirqs_off);
```

它只是调用了 `trace_hardirqs_off_caller` 函数。`trace_hardirqs_off_caller` 检查当前进程的 `hardirqs_enabled` 字段，如果 `local_irq_disable` 是冗余的，或者不是 `hardirqs_off_events`，就增加 `redundant_hardirqs_off`。这两个字段和其它 `lockdep` 统计相关的字段定义在 [kernel/locking/lockdep_insides.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/locking/lockdep_insides.h) 的 `lockdep_stats` 结构中：and just calls `trace_hardirqs_off_caller` function. The `trace_hardirqs_off_caller` checks the `hardirqs_enabled` field of the current process and increases the `redundant_hardirqs_off` if call of the `local_irq_disable` was redundant or the `hardirqs_off_events` if it was not. These two fields and other `lockdep` statistic related fields are defined in the [kernel/locking/lockdep_insides.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/locking/lockdep_insides.h) and located in the `lockdep_stats` structure:

```C
struct lockdep_stats {
...
...
...
int     softirqs_off_events;
int     redundant_softirqs_off;
...
...
...
}
```

如果你要设置 `CONFIG_DEBUG_LOCKDEP` 内核配置项，`lockdep_stats_debug_show` 函数会把所有的跟踪信息写入 `/proc/lockdep`：If you will set `CONFIG_DEBUG_LOCKDEP` kernel configuration option, the `lockdep_stats_debug_show` function will write all tracing information to the `/proc/lockdep`:

```C
static void lockdep_stats_debug_show(struct seq_file *m)
{
#ifdef CONFIG_DEBUG_LOCKDEP
	unsigned long long hi1 = debug_atomic_read(hardirqs_on_events),
	                         hi2 = debug_atomic_read(hardirqs_off_events),
							 hr1 = debug_atomic_read(redundant_hardirqs_on),
    ...
	...
	...
    seq_printf(m, " hardirq on events:             %11llu\n", hi1);
    seq_printf(m, " hardirq off events:            %11llu\n", hi2);
    seq_printf(m, " redundant hardirq ons:         %11llu\n", hr1);
#endif
}
```

并且，你可以看到如下结果：and you can see its result with the:

```
$ sudo cat /proc/lockdep
 hardirq on events:             12838248974
 hardirq off events:            12838248979
 redundant hardirq ons:               67792
 redundant hardirq offs:         3836339146
 softirq on events:                38002159
 softirq off events:               38002187
 redundant softirq ons:                   0
 redundant softirq offs:                  0
```

好的，关于跟踪现在我们了解点了，但更多的信息将在另外的关于 `lockdep` 和 `tracing` 中（介绍）。你可以在 `local_disable_irq` 宏中看到相同的部分 - `raw_local_irq_disable`。这个宏在 [arch/x86/include/asm/irqflags.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/irqflags.h) 中定义，并扩展为如下调用：Ok, now we know a little about tracing, but more info will be in the separate part about `lockdep` and `tracing`. You can see that the both `local_disable_irq` macros have the same part - `raw_local_irq_disable`. This macro defined in the [arch/x86/include/asm/irqflags.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/irqflags.h) and expands to the call of the:

```C
static inline void native_irq_disable(void)
{
        asm volatile("cli": : :"memory");
}
```

而且，你一定记得 `cli` 指令清除 [IF](http://en.wikipedia.org/wiki/Interrupt_flag) 标志，该标志决定了处理器处理中断或异常的能力。除了 `local_irq_disable`，你已经知道了还有一个相反的宏 - `local_irq_enable`。这个宏有相同的跟踪机制，和 `local_irq_enable` 非常类似，但是如你从它的名字所理解的，它使用 `sti` 指令使能中断：And you already must remember that `cli` instruction clears the [IF](http://en.wikipedia.org/wiki/Interrupt_flag) flag which determines ability of a processor to handle an interrupt or an exception. Besides the `local_irq_disable`, as you already can know there is an inverse macro - `local_irq_enable`. This macro has the same tracing mechanism and very similar on the `local_irq_enable`, but as you can understand from its name, it enables interrupts with the `sti` instruction:

```C
static inline void native_irq_enable(void)
{
        asm volatile("sti": : :"memory");
}
```

现在我们知道 `local_irq_disable` 和 `local_irq_enable` 是如何工作的。这是 `local_irq_disable` 宏的第一次调用，然而我们在 Linux 内核源码中将会多次遇到这些宏。但是现在我们在 [init/main.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/init/main.c) 中的 `start_kernel` 函数中，我们只是禁用了`本地`中断。为什么是`本地`的？我们为什么要这么做？以前内核提供了一种方法来禁所有用处理器上N的中断，称之为 `cli`。这个函数已经被[移除](https://lwn.net/Articles/291956/)，现在我们有 `local_irq_{enabled,disable}` 来禁用或启用当前处理器上的中断。在使用 `local_irq_disable` 宏禁用中断后，我们设置：Now we know how `local_irq_disable` and `local_irq_enable` work. It was the first call of the `local_irq_disable` macro, but we will meet these macros many times in the Linux kernel source code. But for now we are in the `start_kernel` function from the [init/main.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/init/main.c) and we just disabled `local` interrupts. Why local and why we did it? Previously kernel provided a method to disable interrupts on all processors and it was called `cli`. This function was [removed](https://lwn.net/Articles/291956/) and now we have `local_irq_{enabled,disable}` to disable or enable interrupts on the current processor. After we've disabled the interrupts with the `local_irq_disable` macro, we set the:

```C
early_boot_irqs_disabled = true;
```

The `early_boot_irqs_disabled` variable defined in the [include/linux/kernel.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/kernel.h):

```C
extern bool early_boot_irqs_disabled;
```

并且该变量是在不同的地方使用的。例如：在 [kernel/smp.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/smp.c) 中的 `smp_call_function_many` 函数中使用，用于当中断禁用时检查可能的死锁：and used in the different places. For example it used in the `smp_call_function_many` function from the [kernel/smp.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/kernel/smp.c) for the checking possible deadlock when interrupts are disabled:

```C
WARN_ON_ONCE(cpu_online(this_cpu) && irqs_disabled()
                     && !oops_in_progress && !early_boot_irqs_disabled);
```

内核初始化期间早期陷阱初始化Early trap initialization during kernel initialization
--------------------------------------------------------------------------------

`local_disable_irq` 之后的下一个函数是 `boot_cpu_init` 和 `page_address_init`，但它们与中断和异常无关（更多关于这个函数的信息，你可以阅读 Linux 内核[初始化过程](http://0xax.gitbooks.io/linux-insides/content/Initialization/index.html)）。接下来是 `setup_arch` 函数。你应该记得，这个函数位于 [arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel.setup.c) 源码文件中，并且做了很多不同架构相关的[事情](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-4.html)。在 `setup_arch` 中我们可以看到的第一个中断相关的函数是 - `early_trap_init` 函数。这个函数定义在 [arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/traps.c) 中，兵用两个条目来填写`中断描述符表`：The next functions after the `local_disable_irq` are `boot_cpu_init` and `page_address_init`, but they are not related to the interrupts and exceptions (more about this functions you can read in the chapter about Linux kernel [initialization process](http://0xax.gitbooks.io/linux-insides/content/Initialization/index.html)). The next is the `setup_arch` function. As you can remember this function located in the [arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel.setup.c) source code file and makes initialization of many different architecture-dependent [stuff](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-4.html). The first interrupts related function which we can see in the `setup_arch` is the - `early_trap_init` function. This function defined in the [arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/traps.c) and fills `Interrupt Descriptor Table` with the couple of entries:

```C
void __init early_trap_init(void)
{
        set_intr_gate_ist(X86_TRAP_DB, &debug, DEBUG_STACK);
        set_system_intr_gate_ist(X86_TRAP_BP, &int3, DEBUG_STACK);
#ifdef CONFIG_X86_32
        set_intr_gate(X86_TRAP_PF, page_fault);
#endif
        load_idt(&idt_descr);
}
```

在这里我们可以看到三个不同的函数调用：Here we can see calls of three different functions:

* `set_intr_gate_ist`
* `set_system_intr_gate_ist`
* `set_intr_gate`

所有这些函数定义在 [arch/x86/include/asm/desc.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/desc.h) 中，做着相似但不相同的事情。第一个 `set_intr_gate_ist` 函数在 `IDT` 中插入一个中断门。让我们来看下它的实现：All of these functions defined in the [arch/x86/include/asm/desc.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/include/asm/desc.h) and do the similar thing but not the same. The first `set_intr_gate_ist` function inserts new an interrupt gate in the `IDT`. Let's look on its implementation:

```C
static inline void set_intr_gate_ist(int n, void *addr, unsigned ist)
{
        BUG_ON((unsigned)n > 0xFF);
        _set_gate(n, GATE_INTERRUPT, addr, 0, ist, __KERNEL_CS);
}
```

首先我们可以看到检查中断[向量号](http://en.wikipedia.org/wiki/Interrupt_vector_table) `n` 是否大于 `0xff` 或 255。我们需要检查一下，因为我们记得在上一[部分](http://0xax.gitbooks.io/linux-insides/content/interrupts/interrupts-1.html)中中断向量号必须在 `0` 和 `255` 之间。在下一步中我们可以看到调用 `_set_gate` 函数，将一个给定的中断门设置到 `IDT` 表：First of all we can see the check that `n` which is [vector number](http://en.wikipedia.org/wiki/Interrupt_vector_table) of the interrupt is not greater than `0xff` or 255. We need to check it because we remember from the previous [part](http://0xax.gitbooks.io/linux-insides/content/interrupts/interrupts-1.html) that vector number of an interrupt must be between `0` and `255`. In the next step we can see the call of the `_set_gate` function that sets a given interrupt gate to the `IDT` table:

```C
static inline void _set_gate(int gate, unsigned type, void *addr,
                             unsigned dpl, unsigned ist, unsigned seg)
{
        gate_desc s;

        pack_gate(&s, type, (unsigned long)addr, dpl, ist, seg);
        write_idt_entry(idt_table, gate, &s);
        write_trace_idt_entry(gate, &s);
}
```

这里我们从 `pack_gate` 函数开始，它采用了由 `gate_desc` 结构表示的干净的 `IDT` 项，并用基址和限制、[中断堆栈表](https://www.kernel.org/doc/Documentation/x86/x86_64/kernel-stacks), [特权等级](http://en.wikipedia.org/wiki/Privilege_level)、中断类型来填充它，其中中断类型可以是以下其中之一的值：Here we start from the `pack_gate` function which takes clean `IDT` entry represented by the `gate_desc` structure and fills it with the base address and limit, [Interrupt Stack Table](https://www.kernel.org/doc/Documentation/x86/x86_64/kernel-stacks), [Privilege level](http://en.wikipedia.org/wiki/Privilege_level), type of an interrupt which can be one of the following values:

* `GATE_INTERRUPT`
* `GATE_TRAP`
* `GATE_CALL`
* `GATE_TASK`

并为给定的 `IDT` 项设置当前位：and set the present bit for the given `IDT` entry:

```C
static inline void pack_gate(gate_desc *gate, unsigned type, unsigned long func,
                             unsigned dpl, unsigned ist, unsigned seg)
{
        gate->offset_low        = PTR_LOW(func);
        gate->segment           = __KERNEL_CS;
        gate->ist               = ist;
        gate->p                 = 1;
        gate->dpl               = dpl;
        gate->zero0             = 0;
        gate->zero1             = 0;
        gate->type              = type;
        gate->offset_middle     = PTR_MIDDLE(func);
        gate->offset_high       = PTR_HIGH(func);
}
```

之后我们使用 `write_idt_entry` 宏将刚刚填充的中断门写到 `IDT` 表，该宏扩展为 `native_write_idt_entry`，并且只是将给定索引的中断门拷贝到 `idt_table` 表：After this we write just filled interrupt gate to the `IDT` with the `write_idt_entry` macro which expands to the `native_write_idt_entry` and just copy the interrupt gate to the `idt_table` table by the given index:

```C
#define write_idt_entry(dt, entry, g)           native_write_idt_entry(dt, entry, g)

static inline void native_write_idt_entry(gate_desc *idt, int entry, const gate_desc *gate)
{
        memcpy(&idt[entry], gate, sizeof(*gate));
}
```

其中 `idt_table` 就是个 `gate_desc` 数组：where `idt_table` is just array of `gate_desc`:

```C
extern gate_desc idt_table[];
```

就这样了。第二个 `set_system_intr_gate_ist` 函数和 `set_intr_gate_ist` 只有一处不同：That's all. The second `set_system_intr_gate_ist` function has only one difference from the `set_intr_gate_ist`:

```C
static inline void set_system_intr_gate_ist(int n, void *addr, unsigned ist)
{
        BUG_ON((unsigned)n > 0xFF);
        _set_gate(n, GATE_INTERRUPT, addr, 0x3, ist, __KERNEL_CS);
}
```

看到了吗？请看 `_set_gate` 的第四个参数。这里是 `0x3`。在 `set_intr_gate` 中是 `0x0`。我们知道这个参数表示 `DPL`，即特权等级。我们还知道 `0` 是最高特权等级，`3` 是最低特权等级。现在我们知道了 `set_system_intr_gate_ist`、`set_intr_gate_ist`、`set_intr_gate` 是如何工作的，我们可以返回 `early_trap_init` 函数了。让我们再来看一下：Do you see it? Look on the fourth parameter of the `_set_gate`. It is `0x3`. In the `set_intr_gate` it was `0x0`. We know that this parameter represent `DPL` or privilege level. We also know that `0` is the highest privilege level and `3` is the lowest.Now we know how `set_system_intr_gate_ist`, `set_intr_gate_ist`, `set_intr_gate` are work and we can return to the `early_trap_init` function. Let's look on it again:

```C
set_intr_gate_ist(X86_TRAP_DB, &debug, DEBUG_STACK);
set_system_intr_gate_ist(X86_TRAP_BP, &int3, DEBUG_STACK);
```

我们为 `#DB` 和 `int3` 中断设置了 `IDT` 项。这些函数具有相同的参数集合：We set two `IDT` entries for the `#DB` interrupt and `int3`. These functions takes the same set of parameters:

* 中断向量号；vector number of an interrupt;
* 中断处理程序地址；address of an interrupt handler;
* 中断堆栈表索引。interrupt stack table index.

就这么多了。有关中断和处理程序的更多信息，你将在下面的部分了解。That's all. More about interrupts and handlers you will know in the next parts.

结论Conclusion
--------------------------------------------------------------------------------

关于 Linux 内核中断和中断处理的第二部分就结束了。我们看了上一部分的一些理论，并开始深入本部分的中断和异常处理。我们是从最早与中断相关的 Linux 内核源码开始的。在下一部分，我们将继续深入研究这一有趣的主题，并了解更多关于中断处理程序的信息。It is the end of the second part about interrupts and interrupt handling in the Linux kernel. We saw the some theory in the previous part and started to dive into interrupts and exceptions handling in the current part. We have started from the earliest parts in the Linux kernel source code which are related to the interrupts. In the next part we will continue to dive into this interesting theme and will know more about interrupt handling process.

If you have any questions or suggestions write me a comment or ping me at [twitter](https://twitter.com/0xAX).

**Please note that English is not my first language, And I am really sorry for any inconvenience. If you find any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-insides).**

链接Links
--------------------------------------------------------------------------------

* [IDT](http://en.wikipedia.org/wiki/Interrupt_descriptor_table)
* [Protected mode](http://en.wikipedia.org/wiki/Protected_mode)
* [List of x86 calling conventions](http://en.wikipedia.org/wiki/X86_calling_conventions#List_of_x86_calling_conventions)
* [8086](http://en.wikipedia.org/wiki/Intel_8086)
* [Long mode](http://en.wikipedia.org/wiki/Long_mode)
* [NX](http://en.wikipedia.org/wiki/NX_bit)
* [Extended Feature Enable Register](http://en.wikipedia.org/wiki/Control_register#Additional_Control_registers_in_x86-64_series)
* [Model-specific register](http://en.wikipedia.org/wiki/Model-specific_register)
* [Process identifier](https://en.wikipedia.org/wiki/Process_identifier)
* [lockdep](http://lwn.net/Articles/321663/)
* [irqflags tracing](https://www.kernel.org/doc/Documentation/irqflags-tracing.txt)
* [IF](http://en.wikipedia.org/wiki/Interrupt_flag)
* [Stack canary](http://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries)
* [Union type](http://en.wikipedia.org/wiki/Union_type)
* [this_cpu_* operations](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/Documentation/this_cpu_ops.txt)
* [vector number](http://en.wikipedia.org/wiki/Interrupt_vector_table)
* [Interrupt Stack Table](https://www.kernel.org/doc/Documentation/x86/x86_64/kernel-stacks)
* [Privilege level](http://en.wikipedia.org/wiki/Privilege_level)
* [Previous part](http://0xax.gitbooks.io/linux-insides/content/interrupts/interrupts-1.html)
