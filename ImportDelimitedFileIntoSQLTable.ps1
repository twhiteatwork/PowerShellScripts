####################################################
#
# PowerShell Import Delimited File into SQL Table Script
#
####################################################

Param(
    # Database variables
    [string]$SQLServer,
    [string]$Database,
    [string]$DBLoginName,
    [string]$DBLoginPwd,
    [string]$Table,
    [boolean]$TruncateTable = $false,

    # Delimited file variables
    [string]$DelimitedFile,
    [string]$ColumnDelimiter = "`t",
    [boolean]$FirstRowColumnNames
)

# Check parameters
if ([string]::IsNullOrEmpty($SQLServer)) {Write-Host "SQLServer parameter must not be null or empty";exit 1;}
if ([string]::IsNullOrEmpty($Database)) {Write-Host "Database parameter must not be null or empty";exit 1;}
if ([string]::IsNullOrEmpty($DBLoginName)) {Write-Host "DBLoginName parameter must not be null or empty";exit 1;}
if ([string]::IsNullOrEmpty($DBLoginPwd)) {Write-Host "DBLoginPwd parameter must not be null or empty";exit 1;}
if ([string]::IsNullOrEmpty($Table)) {Write-Host "Table parameter must not be null or empty";exit 1;}
if ([string]::IsNullOrEmpty($DelimitedFile)) {Write-Host "DelimitedFile parameter must not be null or empty";exit 1;}
if ([string]::IsNullOrEmpty($ColumnDelimiter)) {Write-Host "DelimitedFile parameter must not be null or empty";exit 1;}
if ([string]::IsNullOrEmpty($FirstRowColumnNames)) {Write-Host "DelimitedFile parameter must not be null or empty";exit 1;}

################### No need to modify anything below ###################
Write-Host "Starting import of '$DelimitedFile' into SQL table '$Table'"
#$elapsed = [System.Diagnostics.Stopwatch]::StartNew()
[void][Reflection.Assembly]::LoadWithPartialName("System.Data")
[void][Reflection.Assembly]::LoadWithPartialName("System.Data.SqlClient")

# 50k worked fastest and kept memory usage to a minimum
$BatchSize = 1000

# Build the sqlbulkcopy connection, and set the timeout to infinite
$ConnectionString = "Data Source=$SQLServer;Initial Catalog=$Database;user=$DBLoginName;password=$DBLoginPwd"
$SQLBulkCopy = New-Object Data.SqlClient.SqlBulkCopy($ConnectionString, [System.Data.SqlClient.SqlBulkCopyOptions]::TableLock)
$SQLBulkCopy.DestinationTableName = $Table
$SQLBulkCopy.bulkcopyTimeout = 0
$SQLBulkCopy.batchsize = $BatchSize

# Create the datatable, and autogenerate the columns.
$DataTable = New-Object System.Data.DataTable

# Open the text file from disk
$StreamReader = New-Object System.IO.StreamReader($DelimitedFile)
$Columns = (Get-Content $DelimitedFile -First 1).Split($ColumnDelimiter)
if ($FirstRowColumnNames -eq $true) { $Null = $StreamReader.readLine() }

foreach ($Column in $Columns) {
    $Null = $DataTable.Columns.Add()
}

# Truncate target table
if ($TruncateTable -eq $true) {
    Write-Host "Truncating table '$Table'"
    $DatabaseConnection = New-Object System.Data.SqlClient.SqlConnection
    $DatabaseConnection.ConnectionString = $ConnectionString
    $DatabaseConnection.Open()
    $DatabaseCommand = New-Object System.Data.SqlClient.SqlCommand
    $DatabaseCommand.Connection = $DatabaseConnection
    $DatabaseCommand.CommandText = "TRUNCATE TABLE $Table"
    $NonQueryResult = $DatabaseCommand.ExecuteNonQuery()
    $DatabaseCommand.Dispose()
    $DatabaseConnection.Close(); $DatabaseConnection.Dispose()
}

# Read in the data, line by line, not column by column
$i = 0;
while (($Line = $StreamReader.ReadLine()) -ne $Null)  {
    #Write-Host $Line
    try {
        $Null = $DataTable.Rows.Add($Line.Split($ColumnDelimiter))
    }
    catch {
        Write-Host "ERROR: Unable to add line: $Line.Split($ColumnDelimiter)" 
    }

    # Import and empty the datatable before it starts taking up too much RAM, but
    # after it has enough rows to make the import efficient.
    $i++; if (($i % $BatchSize) -eq 0) {
        #Write-Host "Attempting Row $i"

        try {
            $SQLBulkCopy.WriteToServer($DataTable)
        }
        catch {
            Write-Host "ERROR: Unable to add line: $i"
        }
        #Write-Host "$i rows have been inserted in $($elapsed.Elapsed.ToString())."
        $DataTable.Clear()
    }
}
 
# Add in all the remaining rows since the last clear
if($DataTable.Rows.Count -gt 0) {
    $SQLBulkCopy.WriteToServer($DataTable)
    $DataTable.Clear()
}
 
# Clean Up
$StreamReader.Close(); $StreamReader.Dispose()
$SQLBulkCopy.Close(); $SQLBulkCopy.Dispose()
$DataTable.Dispose()

Write-Host "Finished importing $i rows from '$DelimitedFile' into SQL table '$Table'"
#Write-Host "Total Elapsed Time: $($elapsed.Elapsed.ToString())"
# Sometimes the Garbage Collector takes too long to clear the huge datatable.
[System.GC]::Collect()