EXES := DuoVerify.exe DuoAdmin.exe

all: $(EXES)

%.exe: %.cs ../Duo.cs
	dmcs -r:System.Web.Services -r:System.Web.Extensions -r:System.Web $< ../Duo.cs -out:$@

clean:
	rm -f $(EXES) *~
