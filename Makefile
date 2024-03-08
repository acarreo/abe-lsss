.PHONY: all install clean

CC = cc
CXX = g++
CXXFLAGS = -Wall
LIB_LSSS = liblsss.a
SRC = $(wildcard lsss/*.cpp)
OBJ = $(SRC:.cpp=.o)
INSTALL_DIR = /usr/local
# RELIC_INCLUDE = /usr/local/include/relic

all: install

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXXFLAGS)

zparser.tab.o: lsss/zparser.tab.cc
	$(CC) -o $@ -c $< $(CXXFLAGS)

$(LIB_LSSS): $(OBJ) lsss/zparser.tab.o
	ar rcs $@ $^

install-lsss: $(LIB_LSSS)
	sudo mkdir -p $(INSTALL_DIR)/include/lsss
	sudo cp lsss/*.h lsss/zparser.yy lsss/zparser.tab.hh lsss/zscanner.ll $(INSTALL_DIR)/include/lsss/
	sudo mv $(LIB_LSSS) $(INSTALL_DIR)/lib

install-relic:
	./compile/install-relic.sh

install: install-lsss install-relic

clean:
	rm -f *.o lsss/*.o *.a *~
