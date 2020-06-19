bin_PROGRAMS=spritz
spritz_SOURCES=src/main.c src/hash.c src/b64.c \
               src/spritz.c src/spritz.h src/crypt.c
# info_TEXINFOS=
# dist_man1_MANS=spritz.1
dist_check_SCRIPTS=test/hash-test.sh test/crypt-test.sh
#dist_check_DATA=
TESTS=$(dist_check_SCRIPTS)

indent: $(spritz_SOURCES)
	indent $(spritz_SOURCES) --no-tabs

.PHONY: indent
