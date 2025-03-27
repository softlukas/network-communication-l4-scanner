PROJECT = src/proj1.csproj

all: clean publish

publish:
	dotnet publish $(PROJECT) -r linux-x64 -c Release -o .

clean:
	rm -rf src/bin
	rm -rf src/obj
