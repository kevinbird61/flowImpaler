EXEC:=flowimpaler
THIRD:=xxhash.o
LIBS:=hash.o
OBJS:=sh.o
CXXFLAGS:= -std=c++11

all: $(EXEC)

# executable
$(EXEC): $(OBJS) $(LIBS) $(THIRD) main.cc
	g++ $^ -o $@ -Isrc -Ilib -Ithird_party $(CXXFLAGS) -lpcap -lm

# third party
$(THIRD): %.o: third_party/%.c 
	gcc -c $^ -o $@

# objectives (wrote in C++)
$(OBJS): %.o: src/%.cc 
	g++ -c $^ -Ilib -o $@ $(CXXFLAGS)

# libraries (wrote in C)
$(LIBS): %.o: lib/%.c
	gcc -c $^ -o $@ 

clean: 
	rm -rf $(OBJS) $(LIBS) $(EXEC) $(THIRD)