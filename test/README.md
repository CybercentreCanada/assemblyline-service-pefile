build hello world .net exe using builtin csc compiler
https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/hello-world-your-first-program


download windows sdk https://www.microsoft.com/en-us/download/confirmation.aspx?id=6510
 
use makecert stuff from https://www.meziantou.net/2017/03/25/generate-a-self-signed-certificate-for-code-signing
 
then follow instructions from https://knowledge.digicert.com/solution/SO4699.html
 
makecert.exe -r -pe -n "CN=Sample.CA" -ss CA -sr CurrentUser -a sha1 -cy authority -sky signature -sv c:\Sample.CA.pvk c:\Sample.CA.cer
 
certutil.exe -user -addstore Root c:\Sample.CA.cer
 
REM Create the certificate for code signing
makecert.exe -pe -n "CN=Sample.CodeSigning" -eku "1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.13" -a sha1 -cy end -sky signature -ic c:\Sample.CA.cer -iv c:\Sample.CA.pvk -sv c:\Sample.CodeSigning.pvk c:\Sample.CodeSigning.cer
 
REM Convert to certificate to pfx file format
pvk2pfx.exe -pvk c:\Sample.CodeSigning.pvk -spc c:\Sample.CodeSigning.cer -pfx c:\Sample.CodeSigning.pfx


====

disitool - installed, had to pip install pefile2 along with it for it to work

copied a signature, verify sigs doesn't work now