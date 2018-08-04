# Edit the following defines and type make.

# Set to a valid DCE account
USERNAME=username

# Set to the password for the above account
USERPASS=password

# Set to a file in DFS only accessible by the above user
FILENAME=/dfs/path/to/file


# For Digital DCE 2.0
#LIBS=-ldce

# For Transarc DCE 1.1
#CC=gcc
#LIBS=-ldce -lsocket -lnsl -lthread -lm

# For Transarc DCE 2.0
CC=gcc -I/usr/include/dce -D_REENTRANT
LIBS=-ldce

# For AIX DCE
#CC=xlC_r4 -DAIX
#LIBS=-ldce -bI:../afs_syscall.aix

all: test runtest

test: test.c
	@echo "Building test program"
	@$(CC) -DUSERNAME=\"$(USERNAME)\" -DUSERPASS=\"$(USERPASS)\" \
            -DFILENAME=\"$(FILENAME)\" -o test test.c $(LIBS)

runtest:
	@echo "Running test program"
	@echo "  -- Ignore any messages beginning with 'dfs:'"
	@echo "     Only messages beginning with 'test:' are important"
	@echo
	@./test

clean:
	rm test
