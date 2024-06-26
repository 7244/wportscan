OUTPUT = a.exe

LINK = -lev
INCLUDE = 
CS = -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare

debug:
	clang $(CS) -g wportscan.c -o $(OUTPUT) $(INCLUDE) $(LINK)

release:
	clang $(CS) -s -O3 wportscan.c -o $(OUTPUT) $(INCLUDE) $(LINK)

clean:
	rm $(OUTPUT)
