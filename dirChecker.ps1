<#
.SYNOPSIS
Find new or changed files in a directory compared to a known-good image.

.DESCRIPTION
The script looks for file changes/additions between a production directory (target) with a known-good directory.

.PARAMETER knownGood
Path of the known-good directory.

.PARAMETER productionImage
Path of the production directory (target).

.INPUTS
System.String

.OUTPUTS
System.String

.EXAMPLE
.\dirChecker.ps1 -knownGood <PATH> -productionImage <PATH>
.\dirChecker.ps1 -knownGood .\knownGoodDir\ -productionImage .\targetDir\
.\dirChecker.ps1 -knownGood "D:\release3.0" -productionImage "C:\inetpub\wwwroot"

-- Input --
.\dirChecker.ps1 -knownGood "D:\Users\<user>\Documents\knownGoodDir" -productionImage "C:\Users\<user>\Documents\targetDir"

-- Output --
File analysis started.
Any file listed below is a new or changed file.

C:\Users\<user>\Documents\targetDir\index.html
C:\Users\<user>\Documents\targetDir\research.docx
C:\Users\<user>\Documents\targetDir\inventory.csv
C:\Users\<user>\Documents\targetDir\contactus.js

File analysis completed.

.LINK
https://github.com/nsacyber/MitigatingWebShells
#>

<#
#
# Execution begins.
#
#>
param (
    [Parameter(Mandatory=$TRUE)][ValidateScript({Test-Path $_ -PathType 'Container'})][String] $knownGood,
    [Parameter(Mandatory=$TRUE)][ValidateScript({Test-Path $_ -PathType 'Container'})][String] $productionImage
)

# Recursively get all files in both directories, for each file calculate hash.
$good = Get-ChildItem -Force -Recurse -Path $knownGood | ForEach-Object { Get-FileHash -Path $_.FullName }
$prod = Get-ChildItem -Force -Recurse -Path $productionImage | ForEach-Object { Get-FileHash -Path $_.FullName }

Write-Host "File analysis started."
Write-Host "Any file listed below is a new or changed file.`n"

# Compare files hashes, select new or changed files, and print the path+filename.
(Compare-Object $good $prod -Property hash -PassThru | Where-Object{$_.SideIndicator -eq '=>'}).Path

Write-Host "`nFile analysis completed."
