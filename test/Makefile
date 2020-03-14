.POSIX:
.SUFFIXES: .cpp .o

CXX = g++

BASE_CXXFLAGS = -std=c++11 -Wall -Wextra -fPIC
CXXFLAGS = -O2 -g -D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS -fstack-clash-protection -fstack-protector-all
BASE_LDFLAGS =
LDFLAGS = -Wl,-z,defs -Wl,-z,relro -Wl,-z,now

all: libmgr.so app

.cpp.o:
	$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) -c -o $(@) $(<)

libmgr.so: lib.o
	$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) $(BASE_LDFLAGS) $(LDFLAGS) -shared -o $(@) $(^)

app: app.o
	$(CXX) $(BASE_CXXFLAGS) $(CXXFLAGS) $(BASE_LDFLAGS) $(LDFLAGS) -fPIE -pie -L. -lmgr -Wl,-pie -o $(@) $(^)

clean:
	rm -f *.o
	rm -f libmgr.so
	rm -f app
