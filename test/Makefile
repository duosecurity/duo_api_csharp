DLLS := SigningTest.dll QueryParamsTest.dll

test: $(DLLS)
	nunit-console $^

%.dll: %.cs ../Duo.cs
	dmcs /target:library -r:System.Web.Services -r:System.Web.Extensions -r:System.Web -r:nunit.framework.dll $< ../Duo.cs -out:$@

clean:
	rm -f $(DLLS) *~ TestResult.xml
