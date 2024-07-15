# Download rockyou2024.zip and unpack e. u. using the free version of https://utorrent.com installed in a sandbox VM
# using the Magnet link from https://github.com/exploit-development/RockYou2024.
# If you make the .txt file read-only you may access it from several instances in parallel.
# Developed by Oliver Lohkamp, 2024-07-14

# Define the file path and the position to start reading
$filePath = "E:\temp\testbinarysorted.txt"
$sortedStartingFromOffset = 0
$EolChars = "`r`n" # ASCII CR + LF for Windows files

# Override the test parameters from above with the real password file location and end-of-line characters:
# $filePath = "\\xxx\D\temp\rockyou2024.txt"
$filePath = "D:\temp\rockyou2024.txt"
$sortedStartingFromOffset = 0 # 226,561,320 51,995,926 8,774,701
$EolChars = "`n" # ASCII line feed only

# put your string (starting characters or your password to search) here:
$searchFor = "--xyzasdf" # delete the -- to find something... :-)


# no need to modify this file any further, just start/debug it with Visual Studio Code or directly in a PowerShell window
# to get the search result within a second thanks to binary search even if you access the password file via network

$NumberOfBytes = $searchFor.Length + 2000   # Number of bytes to read in every chunk during binary search
[long] $firstByte = $sortedStartingFromOffset  # normally 0, but first MB of file is not sorted!
[long] $lastByte = (Get-Item -Path $filePath).Length
[long] $fileLength = $lastByte
[long] $firstFound = -1
[long] $foundAt = 0   # init for repeated debugging only
[long] $loopCount = 0

# rockyou2024.txt starts with symbols, then upper, then lower case letters, so apply binary compare
function IsSortedBefore ([string] $string1, [string] $string2, [int] $maxCharactersToCompare = 999) {
    $b1 = [System.Text.Encoding]::UTF8.GetBytes($string1)
    $b2 = [System.Text.Encoding]::UTF8.GetBytes($string2)

    for ($i = 0; $i -lt $maxCharactersToCompare -and $i -lt $b1.Length -and $i -lt $b2.Length; $i++) {
        if ($b1[$i] -lt $b2[$i]) {
            return $true
        } elseif ($b1[$i] -gt $b2[$i]) {
            return $false
        }
    }
    return $i -ne $maxCharactersToCompare -and $b1.Length -lt $b2.Length
}
# IsSortedBefore "abc6def" "abc6def"
# exit

function VerifyCompleteSortOrder($filePath, $fileSize, $startOffset) {
    [long] $i = 0
    $log = 0
    $reader = [System.IO.File]::OpenText($filePath)
    $reader.BaseStream.Seek($startOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
    [long] $bytesRead = $startOffset
    $reader.ReadLine() # dummy - skip first line

    while($null -ne ($line = $reader.ReadLine())) {
        $i++;
        $bytesReadBefore = $bytesRead
        $bytesRead += $line.Length + $EolChars.Length
        if((IsSortedBefore $line $lastLine 3) -eq $true) {
            Write-Host "Line" $i.ToString("N0") ", offeset" $bytesReadBefore.ToString("N0") ": not ascending lines detected:`r`n" $lastLine "`r`n" $line
            break;
        }
        $lastLine = $line
        if($log++ -eq 9999) {
            Write-Host $i.ToString("N0") "lines read," $bytesRead.ToString("N0") "bytes =" ($bytesRead / $fileSize).ToString("P3")
            $log = 0
        }
    }
    $reader.Close()
}

# Enable this to verify that the whole file is binary sorted, at least if you only compare the first 3 characters in each line.
# For most lines you may compare all characters.
# As the sorting is not absolutely perfect in the source file this password search script gives only very very  reliable answers, but not 100 % sure!

# VerifyCompleteSortOrder $filePath $lastByte $sortedStartingFromOffset
# VerifyCompleteSortOrder $filePath $lastByte 0
# exit


# Open the file stream
$fileStream = [System.IO.File]::OpenRead($filePath)
    
# Create a buffer to hold the bytes
$buffer = New-Object byte[] $numberOfBytes

while ($firstByte -lt $lastByte) {
    $loopCount++
    $middle = [long] [Math]::Truncate(($lastByte - $firstByte) / 2) + $firstByte  # Position in bytes
    [long] $startPosition = [Math]::Max($firstByte, [Math]::Max(($middle - $searchFor.Length / 2) - 2, 0))
    $atPercentOfFile = ($startPosition / $fileLength) * 100 # for debug output only
    # $atPercentOfFile
    
    # Set the position in the file stream
    $fileStream.Seek($startPosition, [System.IO.SeekOrigin]::Begin) | Out-Null
    
    # Read the bytes into the buffer
    $fileStream.Read($buffer, 0, $numberOfBytes) | Out-Null

    # Output the bytes, during debugging only
    # $buffer

    # Convert byte array to string
    $string = [System.Text.Encoding]::UTF8.GetString($buffer)

    # Reduce string to first line
    [long] $newLine = $string.IndexOf($EoLChars);
    if ($newLine -ge 0) {
        $string = $string.Remove(0, $newLine + $EolChars.Length)
        $stringWithTail = $string
        [long] $newLine2 = $string.IndexOf($EolChars)
        if ($newLine2 -ge 0) {
            $string = $string.Remove($newLine2)
        }
    }

    # Check if password is found and output.
    # As we are performing a binary search this is not necessarily the first occurrence. So, continue search!
    if ($string.StartsWith($searchFor) -eq $true) {
        $foundStringWithTail = $stringWithTail
        [long] $foundAt = $startPosition + $newLine + $EolChars.Length
        Write-Host $foundAt ":" $string
        if ($firstFound -lt 0 -or $firstFound -gt $foundAt) {
            $firstFound = $foundAt
        }
        $lastByte = $startPosition - 1
    }
    else {
        # cut search rest to half (binary search)
        if ((IsSortedBefore $searchFor $string)) {
            $newLastByte = $startPosition + $newLine - 1
            if($newLastByte -eq $lastByte) {
                break;
            }
            $lastByte = $newLastByte
        }
        else {
            $firstByte = $startPosition + [Math]::Min($searchFor.Length,$searchFor.Length)
        }
    }
}

# Close the file stream
$fileStream.Close()

# output result
if($firstFound -lt 0) {
    Write-Host "`nDone.`n" $searchFor "not found after" $loopCount "loops"
}
else {
    Write-Host "`nDone. First occurrence starts here:`n"
    Write-Host $foundStringWithTail "..."
    Write-Host $searchFor "first occurrence found at" $firstFound after $loopCount loops
}
