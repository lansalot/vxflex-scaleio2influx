<#
.SYNOPSIS
    Query ScaleIO/VxFlex arrays REST API, and push statistics to InfluxDB
    All configuration is done in accompanying JSON file. Just run this, no parameters necessary
.EXAMPLE
    .\Invoke-ScaleIORest.ps1
.LINK
    https://github.com/lansalot/vxflex-scaleio2influx
#>
if (-not  ($PSVersionTable.PSedition -eq 'Core') ) {
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
        $certCallback = @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationCallback
        {
            public static void Ignore()
            {
                if(ServicePointManager.ServerCertificateValidationCallback ==null)
                {
                    ServicePointManager.ServerCertificateValidationCallback += 
                        delegate
                        (
                            Object obj, 
                            X509Certificate certificate, 
                            X509Chain chain, 
                            SslPolicyErrors errors
                        )
                        {
                            return true;
                        };
                }
            }
        }
"@
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
}

Try {
    $Config = (Get-Content "$($PSScriptRoot)\Invoke-ScaleIORestConfig.json" -Raw | ConvertFrom-Json)
    $Gateways = $Config.Gateways
    $Gateways | Add-Member NoteProperty -Name "Token" -Value ""
    $Influx = $Config.Influx
    $InfluxURL = $Influx.ip + "/write?&db=$($Influx.database)&u=$($Influx.Username)&p=$($Influx.password)"
    $spmetrics = $Config.poolmetrics
    $_smtp = $config.alerts
    $smtp = @{}
    $_smtp.PSObject.Properties | ForEach {$smtp[$_.name] = $_.value}
    $_smtp = $null
    $EmailInterval = $Config.Globals.EmailInterval
    $PollingIntervalSec = $Config.Globals.PollingIntervalSec
    $global:LastSMTP = (Get-Date).AddMinutes($EmailInterval * -2)
} catch {
    Write-Warning "Error reading config - abort!"
    SendMail("Problem reading Config script. Please check once and do the needful.")
    exit 1
}
function SendMail ($Message) {
    if ($global:LastSMTP -lt (Get-Date).AddMinutes($EmailInterval * -1)) {
        Write-Debug  "Sending email at $(Get-Date)  Last:$($global:LastSMTP)"
        $smtp.body = "Unhandled exception at $(Get-Date)`r`n$Message`r`n$_"
        $global:LastSMTP = (Get-Date)
        Send-MailMessage @smtp
    } else {
        Write-Debug "Too soon for another email! Last:$($global:LastSMTP)"
    }
}
function Login-ScaleIO($Gateway) {
 
    $credPair = "$($Gateway.username):$($Gateway.password)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    $headers = @{ Authorization = "Basic $encodedCredentials" }
    Try {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            $responseData = Invoke-RESTMethod -Uri "https://$($Gateway.ip)/api/login" -Method Get -Headers $headers -SkipCertificateCheck
        } else {
            $responseData = Invoke-RESTMethod -Uri "https://$($Gateway.ip)/api/login" -Method Get -Headers $headers
        }
    } 
    catch [System.Net.WebException] {
        if ($_.Exception.Response.StatusCode.Value__ -eq 401) {
            Write-Warning "Authentication error on $(IP). Can't go any further. You should fix this, so aborting"
            SendMail "Authentication error on $(IP). Can't go any further. You should fix this, so aborting"
            exit 1
        }
    }
    catch {
        Write-Debug "Unhandled exception"
        SendMail "Unhandled exception in Login-ScaleIO`r`n$($_)`r`n$($_.ScriptStackTrace)"
        Write-Debug $_
    }
    return [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(":" + $responsedata.replace('"','')))
}

Function Perform-Login() {
    ForEach ($GateWay in ($Gateways | Where {$_.enabled})) {
        Write-Host "Obtaining a logon token for $($Gateway.Friendlyname)" -ForegroundColor Green
        $Token = Login-ScaleIO -Gateway $Gateway
        Write-Debug "Set token $Token for $($Gateway.FriendlyName)"
        $Gateway.Token = $Token
    }
}
Function Invoke-ScaleIORestMethod ($Gateway, [String]$URI) {
    $Headers = @{Authorization = "Basic $($Gateway.Token)"}
    try {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            $responseData = Invoke-RESTMethod -uri "https://$($Gateway.ip)$($uri)" -Method Get -Headers $headers -SkipCertificateCheck
        } else {
            $responseData = Invoke-RESTMethod -uri "https://$($Gateway.ip)$($uri)" -Method Get -Headers $headers
        }
        return $responseData
    }
    catch [System.Net.WebException],[Microsoft.Powershell.Commands.HttpResponseException] {
        if ($_.Exception.Response.StatusCode.Value__ -eq 401) {
            # Now, a login token is only valid for 8 hrs, even when in use, so let's get a new one
            Write-Debug "Looks like old logon token expired."
            Perform-Login
            Invoke-ScaleIORestMethod -Gateway $Gateway -URI $uri
    }
    catch {
        Write-Debug "Unhandled exception in Invoke-ScaleIORestMethod"
        SendMail "Unhandled exception in Invoke-ScaleIORestMethod`r`n$($_)`r`n$($_.ScriptStackTrace)"
        Write-Debug $_
        exit 1
    }
}

Function Write-Influx ([String]$Messages) {
    try {
        Write-Debug $InfluxURL
        if ($PSVersionTable.PSEdition -eq 'Core') {
            Invoke-RestMethod -Uri $InFluxURL -Method Post -Body $Messages -TimeoutSec 30 -DisableKeepAlive -SkipCertificateCheck | Out-Null
        } else {
            Invoke-RestMethod -Uri $InFluxURL -Method Post -Body $Messages -TimeoutSec 30 -DisableKeepAlive | Out-Null
        }
    } catch {
        Write-Debug "Error writing to influx`r`n$($_)"
        SendMail "Error writing to influx`r`n$_`r`n$($_.ScriptStackTrace)"
        Write-Debug $_
    }
}
# Initialise some globals
$ProtectionDomains = $null
$StoragePools = @()


Perform-Login

While ($true) {
    $timestamp = [long]((New-TimeSpan -Start (Get-Date -Date '1970-01-01') -End ((Get-Date).ToUniversalTime())).TotalSeconds * 1E9)
    $Error.Clear()
    ForEach ($GateWay in ($Gateways | Where {$_.enabled})) {

        $ProtectionDomains = Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/types/ProtectionDomain/instances"
        ForEach ($ProtectionDomain in $ProtectionDomains) {
            $StoragePools = Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/ProtectionDomain::$($ProtectionDomain.ID)/relationships/StoragePool"
            ForEach ($StoragePool in $StoragePools) {
                $Stats = Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/StoragePool::$($StoragePool.ID)/relationships/Statistics"
                $influxentry = "scaleio,Cluster=$($Gateway.Friendlyname),Pool=$($StoragePool.Name) "
                
                ForEach ($metric in $spmetrics) {
                    if ($metric -match "Bwc$") {
                        if ($Stats.$($metric).numSeconds -ne 0) {
                            $IOPS = [Math]::Round($Stats.$($metric).numOccured / $Stats.$($metric).numSeconds)
                            $thruKB = [Math]::Round($Stats.$($metric).totalWeightInKb / $Stats.$($metric).numSeconds)
                        } else {
                            $IOPS = 0
                            $thruKB = 0
                        }
                        $influxEntry += "$($metric)_IOPS=$($IOPS)i,$($metric)_thruKB=$($thruKB)i,"
                    } else {
                        $value = $Stats.$metric
                        $influxEntry += "$($metric)=$($value)i,"
                    }
                }
                # $influxentry = $influxEntry.Replace(".numOccured","_IOPS")
                # $influxentry = $influxEntry.Replace(".totalWeightInKb","_thruKB")
                $influxentry = $influxentry -replace ".$"
                $influxentry += " $($timestamp)"
                Write-Debug "$influxentry"
                Write-Influx -Messages $influxEntry
            }
        }
    }
    Write-Host "." -NoNewline
    Start-Sleep -Seconds $PollingIntervalSec
}
