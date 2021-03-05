# Binspector
Parse 64-Bit Windows-Compatible binaries without relying on Microsoft-lib dependencies. All information for structures were pulled from Microsoft's public pdb files.
Provides information such as target architecture, process entry point, sections summary, and all imported DLL's and respective named functions.

## Building
Set the Visual Studio solution to build either Debug or Release for x64.

## Usage
$ Binspector [filePath]
Example:
$ Binspector C:\Windows\System32\cmd.exe

## Example Output
Open the file, "example.txt" included in the repo root.
