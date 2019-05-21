EXEC:=flowimpaler
THIRD:=xxhash.o
LIBS:=hash.o
OBJS:=sh.o
CXXFLAGS:= -std=c++11

all: $(EXEC)
.PHONY : clean install uninstall

# executable
$(EXEC): $(LIBS) $(OBJS) $(THIRD) main.cc
	g++ $^ -o $@ -Isrc -Ilib -Ithird_party $(CXXFLAGS) -lpcap -lm -lpthread

# third party
$(THIRD): %.o: third_party/%.c 
	gcc -c $^ -o $@

# objectives (wrote in C++)
$(OBJS): %.o: src/%.cc 
	g++ -c $^ -Ilib -o $@ $(CXXFLAGS) -lm -lpthread

# libraries (wrote in C)
$(LIBS): %.o: lib/%.c
	gcc -c $^ -o $@ 

install:
	install -m 557 $(EXEC) /usr/bin/

uninstall:
	rm /usr/bin/flowimpaler

clean: 
	rm -rf $(OBJS) $(LIBS) $(EXEC) $(THIRD)