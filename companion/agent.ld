/* Flat layout for the agent: agent_main first, then the rest of the code and the constants. */
ENTRY(agent_main)
SECTIONS
{
    . = 0;
    .text : { KEEP(*(.text.entry)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.* COMMON) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.llvm_addrsig) }
}
