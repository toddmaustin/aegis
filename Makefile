CXX      = g++
CXXFLAGS = -std=c++17 -g -Wall -Wextra -O0 -maes -msse4.1 -Wno-unused-but-set-variable -Wno-volatile-register-var
TARGET   = test_aegis
SOURCES  = test_aegis.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

