BIN = bin
SRC = src
CFLAGS = /Z7

manual.exe: {$(SRC)\}manual.cpp
	$(CXX) $(CFLAGS) /Fe$(BIN)\$@ $**

clean:
	del /Q *.obj
	del /Q bin\*