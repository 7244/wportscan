OUTPUT = a.exe

LINK = -lev
INCLUDE = -I include
CS = -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare

debug:
	cc $(CS) -g src/wportscan.c -o $(OUTPUT) $(INCLUDE) $(LINK)

release:
	cc $(CS) -s -O3 src/wportscan.c -o $(OUTPUT) $(INCLUDE) $(LINK)

clean:
	rm $(OUTPUT)
