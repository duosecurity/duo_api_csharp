:: Example script for building without the full Visual Studio

:: Install prerequisites using chocolately package manager
choco install -y visualstudio2019buildtools --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools;includeRecommended" nuget.commandline nunit-console-runner

:: Add build tools to path
IF "'%VSINSTALLDIR%'" EQU "''" (call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat") else (echo "vcvars already set")

:: Restore nuget packages
nuget restore

:: Build debug version of the project
msbuild duo_api_csharp.sln /p:Configuration=Debug /p:Platform="Any CPU"

:: Run unit tests
vstest.console.exe .\test\bin\Debug\DuoApiTest.dll