# Edit the following defines and type make.

# Set to a valid DCE account
USERNAME=user

# Set to the password for the above account
USERPASS=pass

# Set to a file in DFS only accessible by the above user
FILENAME=/dfs/user.file


# For Digital DCE 2.0
LIBS=-ldce

# For Transarc DCE 1.1
#LIBS=-ldce -lsocket -lnsl -lthread -lm

all: test runtest

test: test.c
	@echo "Building test program"
	@gcc -DUSERNAME=\"$(USERNAME)\" -DUSERPASS=\"$(USERPASS)\" \
            -DFILENAME=\"$(FILENAME)\" -o test test.c $(LIBS)

runtest:
	@echo "Running test program"
	@echo "  -- Ignore any messages beginning with 'dfs:'"
	@echo "     Only messages beginning with 'test:' are important"
	@echo
	@./test

clean:
	rm test
