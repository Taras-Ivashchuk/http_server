CC = gcc
EXE = srv_app
OBJS = server_api.o http_api.o config_api.o logger_api.o ssl_api.o main.o
HDRS = server_api.h http_api.h config_api.h logger_api.h ssl_api.h
SRC = server_api.c http_api.c main.c config_api.c logger_api.c ssl_api.c
MBED_TLS_GIT = "https://github.com/Mbed-TLS/mbedtls.git"
MBED_LIB = mbedtls
MBED_LIB_SRC = $(MBED_LIB)/library
MBED_LIB_HDR = $(MBED_LIB)/include/
MBED_STATIC_LIB = lib_mbedtls.a
CPPCHECK = cppcheck
CPPCHECK_INCLUDES = ./src ./
CPPCHECK_SUPPRESSION_FILE = ./.suppress.cppcheck
CFLAGS = -g -Wall

all: $(EXE)
	@echo all: $(EXE)

$(EXE): $(MBED_STATIC_LIB) $(OBJS)
	@echo exe
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(MBED_STATIC_LIB)
	@echo exe: done

%.o : %.c $(HDRS)
	@echo here
	$(CC) $(CFLAGS) -I$(MBED_LIB_HDR) -c $< -o $@ 

$(MBED_STATIC_LIB):
	@echo mbed_static_lib
	./dpds.sh
	@test -d $(MBED_LIB) || git clone $(MBED_TLS_GIT)
	@cd $(MBED_LIB) && git pull
	@cd $(MBED_LIB) && make
	@cd $(MBED_LIB_SRC) && make
	ar rcs $(MBED_STATIC_LIB) $(MBED_LIB_SRC)/*.o
	@echo mbed static lib: done



.PHONY: clean cppcheck

clean:
	rm -rf $(EXE) *.o $(MBED_STATIC_LIB) $(MBED_LIB)
cppcheck:
	$(CPPCHECK) \
	--quiet \
	--enable=all \
	--force \
	--inline-suppr \
	--suppressions-list=$(CPPCHECK_SUPPRESSION_FILE) \
	-I ./$(MBED_LIB_HDR) \
	-i ./$(MBED_LIB) \
	./
