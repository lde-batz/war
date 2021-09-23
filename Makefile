
NAME = war

SRC +=	war.s
SRC +=	header.s

SRC_DIR = srcs/

OBJ_DIR = objects/

OBJ := $(addprefix $(OBJ_DIR), $(SRC:.s=.o))

SRC := $(addprefix $(SRC_DIR), $(SRC))

NASM = nasm -f elf64

CC = ld

OBF = --discard-all

.SILENT:

all : $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(OBF)
	printf '\033[32m[ ✔ ] %s%s\n\033[0m' "Create " $(NAME)

$(OBJ_DIR)%.o: $(SRC_DIR)%.s
	mkdir -p $(OBJ_DIR)
	$(NASM) $< -o $@
	printf '\033[0m[ ✔ ] %s\n\033[0m' "$<"


clean:
	rm -f $(OBJ)
	rm -Rf $(OBJ_DIR)
	printf '\033[31m[ ✔ ] %s%s\n\033[0m' "Clean " $(NAME)

fclean: clean
	rm -f $(NAME)
	printf '\033[31m[ ✔ ] %s%s\n\033[0m' "Fclean " $(NAME)

re: fclean all

.PHONY: all clean fclean re
