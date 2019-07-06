JC = javac
JFLAGS = -cp './src/jar/bcprov-ext-jdk15on-162.jar:.'
JFLAGS2 = -cp '../src/jar/bcprov-ext-jdk15on-162.jar:.'
JAR = https://www.bouncycastle.org/download/bcprov-ext-jdk15on-162.jar
CURRENT_DIR = $(PWD)

default: all

all:
	mkdir -p ./build
	mkdir -p ./src/jar
	cd ./src/jar && wget -N $(JAR)
	$(JC) $(JFLAGS) -d './build' src/*.java

gs:
	cd build && java $(JFLAGS2) RunGroupServer 8765

fs:
	cd build && java $(JFLAGS2) RunFileServer 4321

cl:
	cd build && java $(JFLAGS2) ClientDriver

rb:
	$(JC) $(JFLAGS) -d './build' src/*.java

rball:
	make clean_all
	make all

clean:
	rm -r build

clear:
	rm -r ./build/*.bin
	rm -r ./build/*.key

clean_all:
	rm -r build
	rm -r src/jar

test:
	echo $(CURRENT_DIR)
