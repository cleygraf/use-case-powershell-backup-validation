param (
    # Path to the environment JSON file used to identify the vCenter and Rubrik servers
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [String]$EnvironmentFile,
    # Path to the configuration JSON file used to describe the applications being tested
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [String]$ConfigFile,
    # Path to the folder that contains XML credential files for this build
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [String]$IdentityPath
)

# Synopsis: Pull configuration details from the root config.json file
task GetConfig {
    $script:Environment = Get-Content -Path $EnvironmentFile | ConvertFrom-Json
    $script:Config = Get-Content -Path $ConfigFile | ConvertFrom-Json
    # If a trailing backslash is omitted, this will make sure it's added to correct for future path + filename activities
    if ($IdentityPath.Substring($IdentityPath.Length - 1) -ne '\') {
        $script:IdentityPath += '\'
    }
}

# Synopsis: Establish connectivity to a Rubrik Cluster
task ConnectRubrik {
    Write-Verbose -Message "Importing Credential file: $($IdentityPath + $Environment.rubrikCred)"
    $Credential = Import-Clixml -Path ($IdentityPath + $Environment.rubrikCred)
    $null = Connect-Rubrik -Server $Environment.rubrikServer -Credential $Credential
    Write-Verbose -Message "Rubrik Status: Connected to $($rubrikConnection.server)" -Verbose
}

# Synopsis: Establish connectivity to a VMware vCenter Server
task ConnectVMware {
    Write-Verbose -Message "Importing Credential file: $($IdentityPath + $Environment.vmwareCred)"
    $Credential = Import-Clixml -Path ($IdentityPath + $Environment.vmwareCred)
    $null = Connect-VIServer -Server $Environment.vmwareServer -Credential $Credential
    Write-Verbose -Message "VMware Status: Connected to $($global:DefaultVIServer.Name)" -Verbose
}

# Synopsis: Create a Live Mount of the intended virtual machine(s)
task CreateLiveMount {
    $i = 0
    # Uses a null array of Mount IDs that will be used to track the request process
    [Array]$Script:MountArray = $null
    foreach ($VM in $Config.virtualMachines) {
        # Check if there is already an existing live mount with the same name
        Write-Verbose -Message "$($VM.mountName): Checking for an existing live mount" -Verbose
        if ( ( (Get-RubrikMount | Measure-Object).count -gt 0 ) -AND `
        ( ( Get-RubrikMount | Where-Object { ("$($_.mountedVmId.Trim)" -ne "") -AND ((Get-RubrikVM -ID $_.mountedVmId).name -eq "$($VM.mountName)") } | Measure-Object ).count -gt 0 ) ) {
                throw "The live mount $($VM.mountName) already exists. Please remove manually or call `"clean`" task."
        }  
       $MountRequest = Get-RubrikVM $VM.name |
            Get-RubrikSnapshot -Date (Get-Date) | Where-Object {$_.id} | ForEach-Object {
                New-RubrikMount -Id $_.id -MountName $VM.mountName -PowerOn:$true -DisableNetwork:$true -Confirm:$false
            }
        Write-Verbose -Message "$($Config.virtualMachines[$i].mountName) Request Created: $($MountRequest.id)" -Verbose
        $Script:MountArray += $MountRequest
        $i++
    }
}

# Synopsis: Validate the health of the Live Mount request and power state
task ValidateLiveMount {
    $i = 0
    foreach ($Mount in $MountArray) {
        while ($true) {
            $ValidateRequest = (Get-RubrikRequest -id $Mount.id -Type vmware/vm).status
            $ValidatePowerOn = (Get-VM -Name $Config.virtualMachines[$i].mountName -ErrorAction:SilentlyContinue).PowerState
            Write-Verbose -Message "$($Config.virtualMachines[$i].mountName) Status: Request is $ValidateRequest, PowerState is $ValidatePowerOn" -Verbose
            if ($ValidateRequest -in @('RUNNING','ACQUIRING','QUEUED','FINISHING')) {                
                Start-Sleep 5
            } elseif ($ValidateRequest -eq 'SUCCEEDED' -and $ValidatePowerOn -eq 'PoweredOn') {
                break
            } else {
                throw "$($Config.virtualMachines[$i].mountName) mount failed, exiting Build script. Previously live mounted VMs will continue running"
            }
        }
        $i++
    }
}

# Synopsis: Validate the health of the Live Mount VMware Tools
task ValidateLiveMountTools {
    $i = 0
    foreach ($Mount in $MountArray) {
        while ($true) {
            $ValidateTools = (Get-VM -Name $Config.virtualMachines[$i].mountName).ExtensionData.Guest.ToolsRunningStatus
            Write-Verbose -Message "$($Config.virtualMachines[$i].mountName) VMware Tools Status: $ValidateTools" -Verbose
            if ($ValidateTools -ne 'guestToolsRunning') {
                Start-Sleep 5
            } else {
                break
            }
        }
        $i++
    }
}

task ValidateRemoteScriptExecution {
    $i = 0
    foreach ($Mount in $MountArray) {
        $LoopCount = 1
        # Keeping the guest credential value local since it may only apply to the individual virtual machine in some cases
        # Try per vm guest credentials first
        if ( Get-Variable -Name "$Config.virtualMachines[$i].guestCred" -ErrorAction SilentlyContinue ) {
            Write-Verbose -Message "Importing Credential file: $($IdentityPath + $($Config.virtualMachines[$i].guestCred))" -Verbose
            $GuestCredential = Import-Clixml -Path ($IdentityPath + $($Config.virtualMachines[$i].guestCred))
        }
        # Use global guest credentials
        else {
            Write-Verbose -Message "Importing Credential file: $($IdentityPath + "guestCred.XML")" -Verbose
            $GuestCredential = Import-Clixml -Path ($IdentityPath + "guestCred.XML")
        }
        while ($true) {
            Write-Verbose -Message "Testing script execution on '$($Config.virtualMachines[$i].mountName)', attempt '$LoopCount'..." -Verbose
            $splat = @{
                ScriptText      = 'hostname'
                ScriptType      = 'PowerShell'
                VM              = $Config.virtualMachines[$i].mountName
                GuestCredential = $GuestCredential
            }
            try {
                $VMScript_return = Invoke-VMScript @splat -ErrorAction Stop
                Write-Verbose -Message "ValidateRemoteScriptExecution returned '$VMScript_return'"
                break
            } catch { }
            
            $LoopCount++
            Sleep -Seconds 5
            
            if ($LoopCount -gt 5) {
                throw "Could not execute script on: $($Config.virtualMachines[$i].mountName)..."
            }
        }
        $i++
    }
}

# Synopsis: Move a Live Mount to a test network
task MoveLiveMountNetwork {
    $i = 0
    foreach ($Mount in $MountArray) {
        $SplatNetAdapter = @{
            NetworkName  = $Config.virtualMachines[$i].testNetwork
            Connected    = $true
            Confirm      = $false
        }
        $ValidateNetwork = Get-NetworkAdapter -VM $Config.virtualMachines[$i].mountName |
            Set-NetworkAdapter @SplatNetAdapter
        Write-Verbose -Message "$($Config.virtualMachines[$i].mountName) Network Status: $($ValidateNetwork.NetworkName) is $($ValidateNetwork.ConnectionState)" -Verbose
        $i++
    }
}

# Synopsis: Move a Live Mount to a test address
task MoveLiveMountNetworkAddress {
    $i = 0
    foreach ($Mount in $MountArray) {
        # Keeping the guest credential value local since it may only apply to the individual virtual machine in some cases
        if ( Get-Variable -Name "$Config.virtualMachines[$i].guestCred" -ErrorAction SilentlyContinue ) {
            Write-Verbose -Message "Importing Credential file: $($IdentityPath + $($Config.virtualMachines[$i].guestCred))"
            $GuestCredential = Import-Clixml -Path ($IdentityPath + $($Config.virtualMachines[$i].guestCred))
        }
        else {
            Write-Verbose -Message "Importing Credential file: $($IdentityPath + "guestCred.XML")"
            $GuestCredential = Import-Clixml -Path ($IdentityPath + "guestCred.XML")
        }
        $TestInterfaceMAC = ((Get-NetworkAdapter -VM $Config.virtualMachines[$i].mountName | Select-Object -first 1).MacAddress).ToLower() -replace ":","-"
        $splat = @{
            ScriptText      = 'Get-NetAdapter | where {($_.MacAddress).ToLower() -eq "' + $TestInterfaceMAC + '"} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue;`
                               Get-NetAdapter | where {($_.MacAddress).ToLower() -eq "' + $TestInterfaceMAC + '"} | Get-NetIPAddress | Remove-NetIPAddress -confirm:$false;`
                               Get-NetAdapter | where {($_.MacAddress).ToLower() -eq "' + $TestInterfaceMAC + '"} | Set-NetIPInterface -DHCP Disable;`
                               Get-NetAdapter | where {($_.MacAddress).ToLower() -eq "' + $TestInterfaceMAC + '"} | `
                               New-NetIPAddress -IPAddress ' + $Config.virtualMachines[$i].testIp + ' -PrefixLength ' + $Config.virtualMachines[$i].testSubnet + `
                               ' -DefaultGateway ' + $Config.virtualMachines[$i].testGateway
            ScriptType      = 'PowerShell'
            VM              = $Config.virtualMachines[$i].mountName
            GuestCredential = $GuestCredential
        }
        Write-Verbose -Message "Changing ip of $($Config.virtualMachines[$i].mountName) to $($Config.virtualMachines[$i].testIp)." -Verbose
        $output = Invoke-VMScript @splat -ErrorAction Stop
        $splat = @{
            ScriptText      = '(Get-NetAdapter| where {($_.MacAddress).ToLower() -eq "' + $TestInterfaceMAC + '"} | Get-NetIPAddress -AddressFamily IPv4).IPAddress'
            ScriptType      = 'PowerShell'
            VM              = $Config.virtualMachines[$i].mountName
            GuestCredential = $GuestCredential
        }
        Write-Verbose -Message "Verifying new ip of $($Config.virtualMachines[$i].mountName)." -Verbose
        $output = Invoke-VMScript @splat -ErrorAction Stop
        $new_ip = $($output.ScriptOutput | Out-String).Trim().Split("`r`n")[-1]
        if ( $new_ip -eq $Config.virtualMachines[$i].testIp ) {
            Write-Verbose -Message "$($Config.virtualMachines[$i].mountName) Network Address Status: Assigned to $($new_ip)"
        }
        else {
            throw "$($Config.virtualMachines[$i].mountName) changing ip to $($Config.virtualMachines[$i].testIp) failed (is still $($newip)), exiting Build script. Previously live mounted VMs will continue running"
        }
        $i++
    }
}

# Synopsis: Validate the Live Mount against one or more tests to verify the backup copy is operational
task LiveMountTest {
    $SummaryJsonPath = "./TestSummary.json"
    $TestResults = @()
    $TestsDone = @()
    $i = 0
    foreach ($VM in $Config.virtualMachines) {
        Write-Verbose -Message "$($VM.mountName) Test Status: Loading the following tests - $($VM.tasks)" -Verbose
        # Keeping the guest credential value local since it may only apply to the individual virtual machine in some cases
        # Not all tests will need a guest credential, but it's there in case required
        # Try per vm guest credentials first
        if ( Get-Variable -Name "$Config.virtualMachines[$i].guestCred" -ErrorAction SilentlyContinue ) {
            Write-Verbose -Message "Importing Credential file: $($IdentityPath + $($VM.guestCred))" -Verbose
        $GuestCredential = Import-Clixml -Path ($IdentityPath + $($VM.guestCred))
        }
        # Use global guest credentials
        else {
            Write-Verbose -Message "Importing Credential file: $($IdentityPath + "guestCred.XML")" -Verbose
            $GuestCredential = Import-Clixml -Path ($IdentityPath + "guestCred.XML")
        }
        $newTestRun = @()
        $newTestRun = [PSCustomObject]@{ "Name" = $VM.name }
        # Do the tests one by one
        foreach ($taskToRun in $VM.tasks){
            switch ($taskToRun){
                # Check for open Ports
                "Ports" {
                    foreach ($PortToTest in $VM.Ports){
                        try {
                            Invoke-Build -File .\tests.ps1 -Task Port -Config $VM -GuestCredential $GuestCredential -PortToTest $PortToTest
                            # Test successful
                            $newTestRun | Add-Member -MemberType NoteProperty -Name "Port $($PortToTest)" -Value "successful"
                            $TestsDone += "Port $($PortToTest)"
                        }
                        catch {
                            # Test not successful
                            $newTestRun | Add-Member -MemberType NoteProperty -Name "Port $($PortToTest)" -Value "failed"
                            $TestsDone += "Port $($PortToTest)"
                        }
                    }
                }
                "Services" {
                    foreach ($ServiceToTest in $VM.Services){
                        try {
                            Invoke-Build -File .\tests.ps1 -Task Service -Config $VM -GuestCredential $GuestCredential -ServiceToTest $ServiceToTest
                            $newTestRun | Add-Member -MemberType NoteProperty -Name "Service $($ServiceToTest)" -Value "successful"
                            $TestsDone += "Service $($ServiceToTest)"
                        }
                        catch {
                            # Test not successful
                            $newTestRun | Add-Member -MemberType NoteProperty -Name "Service $($ServiceToTest)" -Value "failed"
                            $TestsDone += "Service $($ServiceToTest)"
                        }
                    }
                }
                "URLs" {
                    foreach ($UrlToTest in $VM.URLs){
                        try {
                            Invoke-Build -File .\tests.ps1 -Task URL -Config $VM -GuestCredential $GuestCredential -UrlToTest $UrlToTest
                            $newTestRun | Add-Member -MemberType NoteProperty -Name "URL $($UrlToTest)" -Value "successful"
                            $TestsDone += "URL $($UrlToTest)"
                        }
                        catch {
                            # Test not successful
                            $newTestRun | Add-Member -MemberType NoteProperty -Name "URL $($UrlToTest)" -Value "failed"
                            $TestsDone += "URL $($UrlToTest)"
                        }
                    }
                }
                # Additional tests defined in tests.ps
                default {    
                    try {
                        Invoke-Build -File .\tests.ps1 -Task $taskToRun -Config $VM -GuestCredential $GuestCredential
                        # Test successful
                        $newTestRun | Add-Member -MemberType NoteProperty -Name "$taskToRun" -Value "successful"
                        $TestsDone += "$taskToRun"
                    }
                    catch {
                        # Test not successful
                        $newTestRun | Add-Member -MemberType NoteProperty -Name "$taskToRun" -Value "failed"
                        $TestsDone += "$taskToRun"
                    }
                }
            }
        }
        $TestResults += $newTestRun
        $i++
    }
    $TestResults | ConvertTo-Json | Set-Content  -Path $SummaryJsonPath
    $TestsDone | %{ if (!([bool]($TestResults[0].PSobject.Properties.name -match "$_"))){ $TestResults[0] | Add-Member -MemberType NoteProperty -Name "$_" -Value ""}}
    [PsCustomObject]$TestResults | Format-Table -AutoSize
}

# Synopsis: Remove any remaining Live Mount artifacts
task Cleanup {
    $i = 0
    foreach ($VM in $Config.virtualMachines) {
        # Remove existing live mounts 
        Write-Verbose -Message "$($VM.mountName): Checking for an existing live mount" -Verbose
        if ( ( (Get-RubrikMount | Measure-Object).count -gt 0) -AND `
        ( ( Get-RubrikMount | Where { ("$($_.mountedVmId.Trim)" -ne "") -AND ((Get-RubrikVM -ID $_.mountedVmId).name -eq "$($VM.mountName)") } | Measure-Object ).count -gt 0 ) ) {
            Get-RubrikMount | where { ("$($_.mountedVmId.Trim)" -ne "") -AND ((Get-RubrikVM -ID $_.mountedVmId).name -eq "$($VM.mountName)") } |
            ForEach-Object {
                [void](Remove-RubrikMount -ID $_.id -Confirm:$False)
                Write-Verbose -Message "$((Get-RubrikVM -ID $_.mountedVmId).name): Request created to remove live mount" -Verbose
            }
        }   
        $i++
    }
}

task 1_Init `
GetConfig

task 2_Connect `
ConnectRubrik,
ConnectVMware

task 3_LiveMount `
CreateLiveMount,
ValidateLiveMount,
ValidateLiveMountTools,
ValidateRemoteScriptExecution

task 4_LiveMountNetwork `
MoveLiveMountNetworkAddress,
MoveLiveMountNetwork

task 5_Testing `
LiveMountTest

task prep `
1_Init,
2_Connect,
3_LiveMount,
4_LiveMountNetwork

task test `
1_Init,
2_Connect,
5_Testing

task clean `
1_Init,
2_Connect,
Cleanup

task . `
1_Init,
2_Connect,
3_LiveMount,
4_LiveMountNetwork,
5_Testing,
Cleanup
