# Overview
[![Build Status](https://github.com/duosecurity/duo_api_csharp/actions/workflows/net-ci.yml/badge.svg?branch=master)](https://github.com/duosecurity/duo_api_csharp/actions)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_api_csharp)](https://github.com/duosecurity/duo_api_csharp/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_api_csharp)](https://github.com/duosecurity/duo_api_csharp/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_api_csharp)](https://github.com/duosecurity/duo_api_csharp/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_api_csharp/blob/master/LICENSE)

**duo_api_csharp** - Demonstration client to call Duo API methods
with .NET and C#.

For more information see our Duo for Developers page:

<https://www.duosecurity.com/api>

## TLS 1.2 and 1.3 Support

Duo_api_csharp uses the .NET libraries for TLS operations.  .NET 4.7 or later is required for TLS 1.2; .NET 4.8 or later is required for TLS 1.3.

In addition, version 1.0.0 of duo_api_csharp is required, since prior versions targeted .NET 4.5 which does not support TLS 1.2 or 1.3.

# Installing
A Windows machine is required to run and test duo_api_csharp.

Development:

```
$ git clone https://github.com/duosecurity/duo_api_csharp.git
$ cd duo_api_csharp
```

# Testing

1. Ensure Windows Visual Studio 2019 is installed on your machine.
2. Open duo_api_csharp in Visual Studio.
3. In your Solution Explorer, select the duo_api_csharp.sln solution node.
4. From there, in your Solution Explorer still, find the unit test project DuoApiTest.csproj.
5. Open the Test Explorer window (Test > Test Explorer).
6. Run the unit tests by selecting on the top test and hitting the Run All button. There should be about 25 tests.
Visit Microsoft's ["Get started with unit testing page"](https://learn.microsoft.com/en-us/visualstudio/test/getting-started-with-unit-testing?view=vs-2022&tabs=dotnet%2Cmstest) for more information and help.
 
# Support

Report any bugs, feature requests, etc. to us directly:
support@duosecurity.com

Have fun!

<http://www.duosecurity.com>
