.PHONY: all install clean

CC = cc
CXX = g++
CXXFLAGS = -Wall
LIB_LSSS = liblsss.a
SRC = $(wildcard lsss/*.cpp)
OBJ = $(SRC:.cpp=.o)
INSTALL_DIR = /usr/local
RELIC_INCLUDE = /usr/local/include/relic

all: $(LIB_LSSS)

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXXFLAGS) -I$(RELIC_INCLUDE)

zparser.tab.o: lsss/zparser.tab.cc
	$(CC) -o $@ -c $< $(CXXFLAGS)

$(LIB_LSSS): $(OBJ) lsss/zparser.tab.o
	ar rcs $@ $^

install: $(LIB_LSSS)
	mkdir -p $(INSTALL_DIR)/include/lsss
	cp lsss/*.h lsss/zparser.yy lsss/zparser.tab.hh lsss/zscanner.ll $(INSTALL_DIR)/include/lsss/
	mv $(LIB_LSSS) $(INSTALL_DIR)/lib

install-relic:
	./compile/install-relic.sh

vars:
	@echo "SRC: $(SRC)"
	@echo "OBJ: $(OBJ)"

clean:
	rm -f *.o *~
