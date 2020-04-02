#Specify Default parameters
Param (
    [ValidateScript({Test-Path $_ -PathType 'Container'})][string]$logDir = "C:\inetpub\logs\",
    [ValidateRange(1,100)][int]$percentile = 5
)

If ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage")
    { Throw "Error: must use Full Language Mode (https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)" }

function analyzeLogs ( $field ) {
    $URIs = @{}
    $files = Get-ChildItem -Path $logDir -File -Recurse 
    If ($files.Length -eq 0)  { "No log files at the given location `n$($_)"; Exit }

    #Parse each file for relevant data. If data not present, continue to next file
    $files | Foreach-Object {
        Try {
            $file = New-Object System.IO.StreamReader -Arg $_.FullName
            $Cols = @()
            While ($line = $file.ReadLine()) {
                If ($line -like "#F*") {
                    $Cols = getHeaders($line) 
                } ElseIf ($Cols.Length -gt 0 -and $line -notlike "#*" ) {
                    $req = $line | ConvertFrom-Csv -Header $Cols  -Delimiter ' '
                    If ( IrrelevantRequest $req ) { Continue; }
                    #If target field seen for this URI, update our data; otherwise create data object for this URI/field
                    If ($URIs.ContainsKey($req.uri) -and $URIs[ $req.uri ].ContainsKey($req.$field) ) 
                        { $URIs[ $req.uri ].Set_Item( $req.$field, $URIs[ $req.uri ][ $req.$field ] + 1 ) }
                    ElseIf ($URIs.ContainsKey($req.uri))  
                        { $URIs[ $req.uri ].Add( $req.$field, 1 ) }
                    Else 
                        { $URIs.Add($req.uri, @{ $($req.$field) = 1 }) }
                }
            }
            $file.close()
        } Catch {
            Echo "Unable to parse log file $($_.FullName)`n$($_)"
        }
    }

    Echo "These URIs are suspicious because they have the least number of $($field)s requesting them:"
    $nth_index = [math]::ceiling( ($URIs.Count) * ([decimal]$percentile / 100)) 

    #Count the unique fields for each URI
    ForEach ($key in $($uris.keys)) { $uris.Set_Item( $key, $uris.$key.Count) }
    $URIs.GetEnumerator() | sort Value | Foreach-Object {
        $uri_i = If (Get-Variable 'uri_i' -Scope Local -ErrorAction Ignore) { $uri_i + 1 } Else { 0 } #initialize/increment counter
        If($uri_i -le $nth_index) { Echo "   $($_.Name) is requested by $($_.Value) $($field)(s)" }
   }
}


Function getHeaders ( $s ) {
    $s = (($s.TrimEnd()) -replace "#Fields: ", "" -replace "-","" -replace "\(","" -replace "\)","")
    $s = $s -replace "scstatus","status" -replace "csuristem","uri" -replace "csUserAgent","agent" -replace "cip","ip"
    Return $s.Split(' ') 
}

Function IrrelevantRequest ( $req ) {
    #Skip requests missing required fields
    ForEach ($val in @("status", "uri","agent","ip"))
        { If ($val -notin $req.PSobject.Properties.Name) { Return $True} }
    #We only care about requests where the server returned success (codes 200-299)
    If ($req.status -lt 200 -or $req.scstatus -gt 299) 
        { Return $True }
    Return $False
}

analyzeLogs "agent"
analyzeLogs "ip"

