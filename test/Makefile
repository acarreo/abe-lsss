CXX = g++
# CXXFLAGS = -I/usr/local/include/relic -I/usr/local/include/lsss 
CXXFLAGS = -std=c++11 -Wall
LDFLAGS = -L/usr/local/lib
LDLIBS = -llsss -lrelic_s -lgmp
GTESTLIBS  = -lgtest -lpthread

SRC = test-policy.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = test-pol

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

test_abe: test_abe.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS) $(GTESTLIBS)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
