<#
    Does nothing much - I just use this to test various calls and methods out
#>


if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
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

Try {
    $Config = (Get-Content "$($PSScriptRoot)\Invoke-ScaleIORestConfig.json" -Raw | ConvertFrom-Json)
    $Gateways = $Config.Gateways
    $Gateways | Add-Member NoteProperty -Name "Token" -Value ""
    $spmetrics = $Config.poolmetrics
} catch {
    Write-Warning "Error reading config - abort!"
    SendMail("Problem reading Config script. Please check and resolve.")
    exit 1
}
function SendMail ($Message) {
    $Message
}
function Login-ScaleIO($Gateway) {
 
    $credPair = "$($Gateway.username):$($Gateway.password)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    $headers = @{ Authorization = "Basic $encodedCredentials" }
    Try {
        $responseData = Invoke-WebRequest -Uri "https://$($Gateway.ip)/api/login" -Method Get -Headers $headers -UseBasicParsing
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
        SendMail ("Unhandled exception in Login-ScaleIO`r`n$($_)")
        Write-Debug $_
    }
    return [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(":" + $responsedata.content.replace('"','')))
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
        $responseData = Invoke-WebRequest -uri "https://$($Gateway.ip)$($uri)" -Method Get -Headers $headers -UseBasicParsing
        return ($responseData.Content | ConvertFrom-Json)
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response.StatusCode.Value__ -eq 401) {
            # Now, a login token is only valid for 8 hrs, even when in use, so let's get a new one
            Write-Host "Looks like old logon token expired." -ForegroundColor Yellow
            Perform-Login
            # and try again...
            $responseData = Invoke-WebRequest -uri "https://$($Gateway.ip)$($uri)" -Method Get -Headers $headers -UseBasicParsing
            return ($responseData.Content | ConvertFrom-Json)
        }
    }
    catch {
        Write-host $_
        exit 1
    }
}


# Initialise some globals
$ProtectionDomains = $null
$StoragePools = @()


Perform-Login

ForEach ($GateWay in ($Gateways | Where {$_.enabled})) {

    #Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances"
    Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/types/System/instances"
#    Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/System::1fa9e58570cb016b/relationships/Sdc"
    #Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/Sdc::29d2d84e00000000/relationships/Statistics"
    #Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/Sdc::29d2d84e00000000/relationships/Volume"
    #Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/Volume::6bab1ae900000003/relationships/Statisticss"
   # Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/StoragePool::f20405f200000001/relationships/Volume"
    #Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/StoragePool::f20405f200000001"
    #$result = Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/types/Sdc/instances"
    #$result = Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/types/Device/instances/action/querySelectedStatistics"
    #$result
    #$result | select -ExpandProperty links
    #($result | select -ExpandProperty mdmCluster).clusterState
    # $ProtectionDomains = Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/types/ProtectionDomain/instances"
    # $ProtectionDomains
    # ForEach ($ProtectionDomain in $ProtectionDomains) {
    #     $StoragePools = Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/ProtectionDomain::$($ProtectionDomain.ID)/relationships/StoragePool"
    #     $StoragePools
    #     ForEach ($StoragePool in $StoragePools) {
    #         $Stats = Invoke-ScaleIORestMethod -Gateway $Gateway -URI "/api/instances/StoragePool::$($StoragePool.ID)/relationships/Statistics"
    #         $Stats
    #     }
    # }
    break # let's just do the first one
}
