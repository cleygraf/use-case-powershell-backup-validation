param(
    $Config,
    $PortToTest,
    $ServiceToTest,
    $UrlToTest,
    [System.Management.Automation.PSCredential]$GuestCredential
)

# 
# Tests running on the local machine, e. g. try to ping the test vm
#
task Ping {
    $progressPreferenceStored = $progressPreference
    $progressPreference = 'SilentlyContinue';
    [void](Test-Connection $Config.testIp -Quiet 6> $null)
    Write-Verbose -Message "PING test: $($Config.testIp)" -Verbose
    assert (Test-Connection $Config.testIp -Quiet 6> $null) "Unable to ping $($Config.mountName)."
    $progressPreference = $progressPreferenceStored
}

task Port {
    if ( $(Get-PSVersion).Major -ge 6 ) { 
        Write-Verbose -Message "PORT test: $($Config.testIp):$($PortToTest)" -Verbose
        assert (Test-Connection $Config.testIp -TCPPort $PortToTest) "Unable to connect to port $($PortToTest) of $($Config.mountName)."
    } 
    else {
        Write-Verbose -Message "PORT test: $($Config.testIp):$($PortToTest)" -Verbose
        assert ((Test-NetConnection $Config.testIp -Port $PortToTest).TcpTestSucceeded) "Unable to connect to port $($PortToTest) of $($Config.mountName)."
    }
}

task URL {
    $time = try{ 
        $request = $null 
        $UrlToTest = $UrlToTest.ToLower()
        $URL = $UrlToTest.Replace("$($Config.mountName.ToLower())", "$($Config.testIp)")
         ## Request the URI, and measure how long the response took. 
        Write-Verbose -Message "URL test: $($URL)" -Verbose
        $result1 = Measure-Command { $request = Invoke-WebRequest -Uri $URL } 
        $result1.TotalMilliseconds 
    }  
    catch 
    { 
        $request = $_.Exception.Response 
        $time = -1 
        assert ($false)"WebRequest $URL failed"
    }   
    $result += [PSCustomObject] @{ 
    Time = Get-Date; 
    Uri = $uri; 
    StatusCode = [int] $request.StatusCode; 
    StatusDescription = $request.StatusDescription; 
    ResponseLength = $request.RawContentLength; 
    TimeTaken =  $time;  
    } 

}

#
# Tests running inside the test vm, e. g. check if a service is running. VMware-tools are used to achieve this.
#
task Service {
    Write-Verbose -Message "SERVICE test: $($ServiceToTest)" -Verbose
    $splat = @{
        ScriptText      = 'if ( Get-Service "' + "$ServiceToTest" + '" -ErrorAction SilentlyContinue ) { Write-Output "running" } else { Write-Output "not running" }'
        ScriptType      = 'PowerShell'
        VM              = $Config.mountName
        GuestCredential = $GuestCredential
    }  
    $output = Invoke-VMScript @splat -ErrorAction Stop
    assert ("$($output.Trim())" -eq "running") "Service $($ServiceToTest) not running on $($Config.mountName)."
}

task .