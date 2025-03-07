CXX      = g++
#CXXFLAGS = -std=c++17 -g -Wall -Wextra -O3 -mno-sse -mno-mmx -mno-avx -mno-avx2 -Wno-unused-but-set-variable -Wno-volatile-register-var -Wno-register -fno-inline
CXXFLAGS = -std=c++17 -g -Wall -Wextra -O3 -maes -msse4.1 -Wno-unused-but-set-variable -Wno-volatile-register-var -Wno-register -fno-inline
TARGET   = test_aegis
SOURCES  = test_aegis.cpp

all: build test

build: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

