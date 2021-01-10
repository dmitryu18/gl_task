
param(
	[parameter(Mandatory = $false)]
	$siteName,

	[parameter(Mandatory = $false)]
	$sitePhysicalPath,
	
	[parameter(Mandatory = $false)]
	$siteAppPoolName,
		
	[parameter(Mandatory = $false)]
	[int]$sitePort,
	
	[parameter(Mandatory = $false)]
	$deploymentUserName,
	
	[parameter(Mandatory = $false)]
	$deploymentUserPassword,
	
	[parameter(Mandatory = $false)]
	$managedRunTimeVersion,	
	
	[parameter(Mandatory = $false)]
	$publishSettingSavePath,
	
	[parameter(Mandatory = $false)]
	$publishSettingFileName
)

Import-LocalizedData -BindingVariable Resources -FileName Resources.psd1

# ==================================


 #constants
 $SCRIPTERROR = 0
 $WARNING = 1
 $INFO = 2
 $logfile = ".\HostingLog-$(get-date -format MMddyyHHmmss).log"

$template = @"
<?xml version="1.0" encoding="utf-8"?>
<publishData>
  <publishProfile
    publishUrl=""
    msdeploySite=""
    destinationAppUrl=""
    mySQLDBConnectionString=""
    SQLServerDBConnectionString=""
    profileName="Default Settings"
    publishMethod="MSDeploy"
    userName=""
	userPWD=""
	savePWD="True"
	/>
</publishData>
"@

#the order is important. Check for apppool name first. Its possible that
#the user gave just a sitename to set permissions. In this case leave apppool emtpy.
#else give a default name to the apppool.
if(!$siteAppPoolName)
{
	if(!$siteName)
	{
		$siteAppPoolName = "WDeployAppPool"
	}
}
else	
{
	$siteAppPoolName = $siteAppPoolName.Trim()
}

#now the sitename check. If its empty give it a default name
if(!$siteName)
{
	$siteName = "WDeploySite"
}
else	
{
	$siteName = $siteName.Trim()
}

if(!$sitePhysicalPath)
{
	$sitePhysicalPath =  $env:SystemDrive + "\inetpub\WDeploySite"
}
else
{
	$sitePhysicalPath = $sitePhysicalPath.Trim()
}

#global variable. Because we need to return two values from MWA from one function. [REF] has bugs. Hence global
$global:sitePath = $sitePhysicalPath
$global:publishURL = $null

# this function does logging
function write-log([int]$type, [string]$info){
        
    $message = $info -f $args
    $logMessage = get-date -format HH:mm:ss
    
	Switch($type){
		$SCRIPTERROR{
            $logMessage = $logMessage + "`t" + $Resources.Error + "`t" +  $message
			write-host -foregroundcolor white -backgroundcolor red $logMessage
		}
		$WARNING{
            $logMessage = $logMessage + "`t" + $Resources.Warning + "`t" +  $message
			write-host -foregroundcolor black -backgroundcolor yellow $logMessage
		}
		default{
            $logMessage = $logMessage + "`t" + $Resources.Info + "`t" +  $message
			write-host -foregroundcolor black -backgroundcolor green  $logMessage
		}
	}
        
	$logMessage >> $logfile
}


function GetPublishSettingSavePath()
{
	if(!$publishSettingFileName)
	{
		$publishSettingFileName = "WDeploy.PublishSettings"
	}
	
	if(!$publishSettingSavePath)
	{
		$publishSettingSavePath = [System.Environment]::GetFolderPath("Desktop")
	}

	if((test-path $publishSettingSavePath) -eq $false)
	{
		write-log $SCRIPTERROR $Resources.FailedToAccessScriptsFolder $publishSettingSavePath
		return $null
	}
	
	return Join-Path $publishSettingSavePath $publishSettingFileName
}

# returns false if OS is not server SKU
 function NotServerOS
 {
    $sku = $((gwmi win32_operatingsystem).OperatingSystemSKU)
    $server_skus = @(7,8,9,10,12,13,14,15,17,18,19,20,21,22,23,24,25)
    
    return ($server_skus -notcontains $sku)
 }

 # gives a user access to an IIS site's scope
 function GrantAccessToSiteScope($username, $websiteName)
{
    trap [Exception]
	{
        write-log $SCRIPTERROR $Resources.FailedToGrantUserAccessToSite $username $websiteName
		return $false
    }
	
	foreach($mInfo in [Microsoft.Web.Management.Server.ManagementAuthorization]::GetAuthorizedUsers($websiteName, $false, 0,[int]::MaxValue))
	{
		if($mInfo.Name -eq $username)
		{
			write-log $INFO $Resources.UserHasAccessToSite $username $websiteName
			return $true
		}
	}
	
	[Microsoft.Web.Management.Server.ManagementAuthorization]::Grant($username, $websiteName, $FALSE) | out-null
	write-log $INFO $Resources.GrantedUserAccessToSite $username $websiteName
	return $true
 }
 
 # gives a user permissions to a file on disk 
 function GrantPermissionsOnDisk($username, $type, $options)
 {
	trap [Exception]
	{
        write-log $SCRIPTERROR $Resources.NotGrantedPermissions $type $username $global:sitePath
    }

	$acl = (Get-Item $global:sitePath).GetAccessControl("Access")
	$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($username, $type, $options, "None", "Allow")
	$acl.AddAccessRule($accessrule)
	set-acl -aclobject $acl $global:sitePath
	write-log $INFO $Resources.GrantedPermissions $type $username $global:sitePath
}
 
 function AddUser($username, $password)
 {
    if(-not (CheckLocalUserExists($username) -eq $true))
    {
        $comp = [adsi] "WinNT://$env:computername,computer" 
		$user = $comp.Create("User", $username)   
		$user.SetPassword($password)
		$user.SetInfo()
        write-log $INFO $Resources.CreatedUser $username
    }
 }
  
 function CheckLocalUserExists($username)
 {
	$objComputer = [ADSI]("WinNT://$env:computername")
	$colUsers = ($objComputer.psbase.children | Where-Object {$_.psBase.schemaClassName -eq "User"} | Select-Object -expand Name)

	$blnFound = $colUsers -contains $username

	if ($blnFound){
		return $true
	}
	else{
		return $false
	}
 }
 
 function CheckIfUserIsAdmin($username)
 {
    $computer = [ADSI]("WinNT://$env:computername,computer")  
    $group = $computer.psbase.children.find("Administrators") 

    $colMembers = $group.psbase.invoke("Members") | %{$_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null)} 
    
    $bIsMember = $colMembers -contains $username
    if($bIsMember)
    {
        return $true
    }
    else
    {
        return $false
    }
 }
 
 function CreateLocalUser($username, $password, $isAdmin)
 {
	AddUser $username $password
	
	if($isAdmin)
    {
        if(-not(CheckIfUserIsAdmin($username) -eq $true))
        {
    		$group = [ADSI]"WinNT://$env:computername/Administrators,group"
    		$group.add("WinNT://$env:computername/$username")
    		write-log $INFO $Resources.AddedUserAsAdmin $username
    	}
        else
        {
            write-log $INFO $Resources.IsAdmin $username
        }
    }

    return $true
 }
 
 function Initialize
 {
    trap [Exception]
    {
        write-log $SCRIPTERROR $Resources.CheckIIS7Installed
        break
    }
    
    $inetsrvPath = ${env:windir} + "\system32\inetsrv\"
    
    [System.Reflection.Assembly]::LoadFrom( $inetsrvPath + "Microsoft.Web.Administration.dll" ) > $null
    [System.Reflection.Assembly]::LoadFrom( $inetsrvPath + "Microsoft.Web.Management.dll" )   > $null 
 }  
 
 function GetPublicHostname()
{
	$ipProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
	if($ipProperties.DomainName -eq "")
	{
		return $ipProperties.HostName
	}
	else
	{
		return "{0}.{1}" -f $ipProperties.HostName, $ipProperties.DomainName
	}
}

function GenerateStrongPassword()
{
   [System.Reflection.Assembly]::LoadWithPartialName("System.Web") > $null
   return [System.Web.Security.Membership]::GeneratePassword(12,4)
}

function GetPublishURLFromBindingInfo($bindingInfo, $protocol, $hostname)
{
	$port = 80
	trap [Exception]
    {
		#return defaults		
		return "http://$hostname"
    }
	
	if(($bindingInfo -match "(.*):(\d*):([^:]*)$") -and
		($Matches.Count -eq 4 ))
	{
		$port = $Matches[2]
		$header = $Matches[3]
		$ipaddress = $Matches[1]
		if($header)
		{
			$hostname = $header
		}
		elseif(($ipaddress) -AND (-not($ipaddress -eq "*")))
		{
			$bracketsArray = @('[',']')
			$hostname  = $ipaddress.Trim($bracketsArray)
		}
		
		if(-not($port -eq 80))
		{
			$hostname = $hostname + ":" + $port
		}
	}
	
	return $protocol + "://" + $hostname
}


function GetUnusedPortForSiteBinding()
{
	[int[]] $portArray = $null
	$serverManager = (New-Object Microsoft.Web.Administration.ServerManager) 
	foreach($site in $serverManager.Sites)
	{
		foreach($binding in $site.Bindings)
		{
			if($binding.IsIPPortHostBinding)
			{
				if($binding.Protocol -match "https?")
				{
					if(($binding.BindingInformation -match "(.*):(\d*):([^:]*)$") -and
					($Matches.Count -eq 4 ))
					{
						$portArray = $portArray + $Matches[2]
					}
				}
			}
		}
	}
	
	if(-not($portArray -eq $null))
	{
		$testPortArray = 8080..8200
		foreach($port in $testPortArray)
		{
			if($portArray -notcontains $port)
			{
				return $port
			}
		}
	}
	
	return 8081 #default
}

function CreateSite($name, $appPoolName, $port, $dotnetVersion)
{
	trap [Exception]
    {
		write-log $SCRIPTERROR $Resources.SiteCreationFailed
        return $false
    }
	
	$hostname = GetPublicHostName
	$global:publishURL = "http://$hostname"
	if(-not($port -eq 80))
	{
		$global:publishURL = $global:publishURL + ":" + $port
	}
	
	$configHasChanges = $false
	$serverManager = (New-Object Microsoft.Web.Administration.ServerManager) 
	
	#appPool might be empty. WHen the user gave just a site name to 
	#set the permissions on. As long as the sitename is not empty
	if($appPoolName)
	{
		$appPool = $serverManager.ApplicationPools[$appPoolName]
		if ($appPool -eq $null)
		{
			$appPool = $serverManager.ApplicationPools.Add($appPoolName)
			$appPool.Enable32BitAppOnWin64 = $true
				
			if( ($dotnetVersion) -and 
			(CheckVersionWithinAllowedRange $dotnetVersion) )
			{
				$appPool.ManagedRuntimeVersion = $dotnetVersion
			}
			$configHasChanges = $true
			write-log $INFO $Resources.AppPoolCreated $appPoolName
		}
		else
		{
			write-log $WARNING $Resources.AppPoolExists $appPoolName
		}
	}

	$newSite = $serverManager.Sites[$name]
	if ($newSite -eq $null)
	{
		$newSite = $serverManager.Sites.Add($name,$global:sitePath, $port)
		$newSite.Applications[0].ApplicationPoolName = $appPool.Name
		if((test-path $global:sitePath) -eq $false)
		{
			[System.IO.Directory]::CreateDirectory($global:sitePath)
		}
		else
		{
			write-log $WARNING $Resources.SiteVirtualDirectoryExists $global:sitePath
		}
		
		$newSite.ServerAutoStart = $true
		$configHasChanges = $true
		write-log $INFO $Resources.SiteCreated $name
	}
	else
	{
		#get virtual directory and siteport
		$global:sitePath = [System.Environment]::ExpandEnvironmentVariables($newSite.Applications["/"].VirtualDirectories["/"].PhysicalPath)
		
		foreach($binding in $newSite.Bindings)
		{
			if($binding.IsIPPortHostBinding)
			{
				if($binding.Protocol -match "https?")
				{
					$global:publishURL = GetPublishURLFromBindingInfo $binding.BindingInformation $binding.Protocol $hostname
				}
			}
		}
		
		if($appPoolName)
		{
			if (-not($newSite.Applications[0].ApplicationPoolName -eq $appPool.Name ))
			{
				$newSite.Applications[0].ApplicationPoolName = $appPool.Name
				write-log $INFO $Resources.SiteAppPoolUpdated $name $appPoolName
			}
			else
			{			
				write-log $INFO $Resources.SiteExists $name $appPoolName
			}
		}
		else
		{
			write-log $INFO $Resources.SiteExists $name $newSite.Applications[0].ApplicationPoolName
		}
	}

	if ($configHasChanges)
	{
		$serverManager.CommitChanges()
	}	
	
	return $true
}

function CheckUserViaLogon($username, $password)
 {
 
 $signature = @'
	[DllImport("advapi32.dll")]
	public static extern int LogonUser(
		string lpszUserName,
		string lpszDomain,
		string lpszPassword,
		int dwLogonType,
		int dwLogonProvider,
		ref IntPtr phToken);
'@ 
 	
 	$type = Add-Type -MemberDefinition $signature  -Name Win32Utils -Namespace LogOnUser  -PassThru
	
	[IntPtr]$token = [IntPtr]::Zero

	$value = $type::LogOnUser($username, $env:computername, $password, 2, 0, [ref] $token)

	if($value -eq 0)
	{
		return $false
	}
	
	return $true
 }

function CheckUsernamePasswordCombination($user, $password)
 {
	if(($user) -AND ($password))
	{
		if(CheckLocalUserExists($user) -eq $true)
		{
			if(CheckUserViaLogon $user $password)
			{
				return $true
			}
			else
			{
				write-Log $SCRIPTERROR $Resources.FailedToValidateUserWithSpecifiedPassword $user
				return $false
			}
		}		
	}
	
	return $true
 }
 
 function CreateProfileXml([string]$nameofSite, [string]$username, $password, [string]$hostname, $pathToSaveFile)
{
	trap [Exception]
    {
		write-log $SCRIPTERROR $Resources.FailedToWritePublishSettingsFile $pathToSaveFile
		return
	}
	
	$xml = New-Object xml
	
	if(Test-Path $pathToSaveFile)
	{
		$xml.Load($pathToSaveFile)
	}
	else
	{
		$xml.LoadXml($template)
	}

	$newProfile = (@($xml.publishData.publishProfile)[0])
	$newProfile.publishUrl = $hostname
	$newProfile.msdeploySite = $nameofSite

	$newProfile.destinationAppUrl = $global:publishURL.ToString()
	$newProfile.userName = $username

	if(-not ($password -eq $null))
	{
		$newProfile.userPWD = $password.ToString()
	}
	else
	{
		write-log $WARNING $Resources.NoPasswordForExistingUserForPublish
	}
	
	$xml.Save($pathToSaveFile)
	
	write-log $INFO $Resources.SavingPublishXmlToPath $pathToSaveFile
}

function CheckVersionWithinAllowedRange($managedVersion)
{
	trap [Exception]
    {
		return $false
	}
	
	$KeyPath = "HKLM:\Software\Microsoft\.NETFramework"
	$key = Get-ItemProperty -path $KeyPath
	$path = $key.InstallRoot
	$files = [System.IO.Directory]::GetFiles($path, "mscorlib.dll", [System.IO.SearchOption]::AllDirectories)
	foreach($file in $files)
	{
		if($file -match "\\(v\d\.\d).\d*\\")
		{
			if($Matches[1] -eq $managedVersion)
			{
				return $true
			}
		}
	}
	return $false
}
 

#================= Main Script =================

 if(NotServerOS)
 {
    write-log $SCRIPTERROR $Resources.NotServerOS
    break
 }

#Remove Site
#if ((Test-Path "IIS:\AppPools\My Pool") -eq $False) {
if ((Test-Path $siteAppPoolName) -eq $False) {
    # Application pool does not exist, create it...
    # ...
    Write-Output "Application pool does not exist"
}
else
{
#Remove-Item iis:\AppPools\$appName -Force -Recurse
Remove-Item $siteAppPoolName
}

#if ((Test-Path "IIS:\Sites\Website1") -eq $False) {
if ((Test-Path $siteName) -eq $False) {
    # Site does not exist, create it...
    # ...
    Write-Output "Application pool does not exist"
}
else
{
#Remove-Item IIS:\Sites\$appName -Force -Recurse
Remove-Item $siteName -Force -Recurse
}

#if ((Test-Path "IIS:\Sites\Website1\MyApp") -eq $False) {
if ((Test-Path $sitePhysicalPath) -eq $False) {
    # App/virtual directory does not exist, create it...
    # ...
    Write-Output "Application pool does not exist"
}
else
{
#Remove-Item $physicalPath$appName -Force -Recurse
Remove-Item $sitePhysicalPath -Force -Recurse
}

Initialize
if(CheckUsernamePasswordCombination $deploymentUserName $deploymentUserPassword)
{
	if(!$sitePort)
	{
		$sitePort = GetUnusedPortForSiteBinding 
	}
	if(CreateSite $siteName $siteAppPoolName $sitePort $managedRunTimeVersion)
	{		
		if(!$deploymentUserName)
		{
			$idx = $siteName.IndexOf(' ')
			if( ($idx -gt 0) -or ($siteName.Length -gt 16))
			{
				$deploymentUserName = "WDeployuser"
			}
			else
			{
				$deploymentUserName = $siteName + "user"
			}
		}
		
		if( (CheckLocalUserExists($deploymentUserName) -eq $true))
		{
			$deploymentUserPassword = $null
		}
		else
		{
			if(!$deploymentUserPassword)
			{
				$deploymentUserPassword = GenerateStrongPassword
			}
		}
		
		
		if(CreateLocalUser $deploymentUserName $deploymentUserPassword $false)
		{
			GrantPermissionsOnDisk $deploymentUserName "FullControl" "ContainerInherit,ObjectInherit"
			
			if(GrantAccessToSiteScope ($env:computername + "\" + $deploymentUserName) $siteName)
			{
				$hostname = GetPublicHostName
				$savePath = GetPublishSettingSavePath
				if($savePath)
				{
					CreateProfileXml $siteName $deploymentUserName $deploymentUserPassword $hostname $savePath
				}
			}
		}
	}
}

# SIG # Begin signature block
# MIIXOgYJKoZIhvcNAQcCoIIXKzCCFycCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUMTfBMLmMGalceqYHYJEgOhPG
# SPSgghIxMIIEYDCCA0ygAwIBAgIKLqsR3FD/XJ3LwDAJBgUrDgMCHQUAMHAxKzAp
# BgNVBAsTIkNvcHlyaWdodCAoYykgMTk5NyBNaWNyb3NvZnQgQ29ycC4xHjAcBgNV
# BAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFJv
# b3QgQXV0aG9yaXR5MB4XDTA3MDgyMjIyMzEwMloXDTEyMDgyNTA3MDAwMFoweTEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWlj
# cm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQC3eX3WXbNFOag0rDHa+SU1SXfA+x+ex0Vx79FG6NSMw2tMUmL0mQLD
# TdhJbC8kPmW/ziO3C0i3f3XdRb2qjw5QxSUr8qDnDSMf0UEk+mKZzxlFpZNKH5nN
# sy8iw0otfG/ZFR47jDkQOd29KfRmOy0BMv/+J0imtWwBh5z7urJjf4L5XKCBhIWO
# sPK4lKPPOKZQhRcnh07dMPYAPfTG+T2BvobtbDmnLjT2tC6vCn1ikXhmnJhzDYav
# 8sTzILlPEo1jyyzZMkUZ7rtKljtQUxjOZlF5qq2HyFY+n4JQiG4FsTXBeyS9UmY9
# mU7MK34zboRHBtGe0EqGAm6GAKTAh99TAgMBAAGjgfowgfcwEwYDVR0lBAwwCgYI
# KwYBBQUHAwMwgaIGA1UdAQSBmjCBl4AQW9Bw72lyniNRfhSyTY7/y6FyMHAxKzAp
# BgNVBAsTIkNvcHlyaWdodCAoYykgMTk5NyBNaWNyb3NvZnQgQ29ycC4xHjAcBgNV
# BAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFJv
# b3QgQXV0aG9yaXR5gg8AwQCLPDyIEdE+9mPs30AwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQUzB3OdgBwW6/x2sROmlFELqNEY/AwCwYDVR0PBAQDAgGGMAkGBSsO
# AwIdBQADggEBAHurrn5KJvLOvE50olgndCp1s4b9q0yUeABN6crrGNxpxQ6ifPMC
# Q8bKh8z4U8zCn71Wb/BjRKlEAO6WyJrVHLgLnxkNlNfaHq0pfe/tpnOsj945jj2Y
# arw4bdKIryP93+nWaQmRiL3+4QC7NPP3fPkQEi4F6ymWk0JrKHG3OI/gBw3JXWjN
# vYBBa2aou7e7jjTK8gMQfHr10uBC33v+4eGs/vbf1Q2zcNaS40+2OKJ8LdQ92zQL
# YjcCn4FqI4n2XGOPsFq7OddgjFWEGjP1O5igggyiX4uzLLehpcur2iC2vzAZhSAU
# DSq8UvRB4F4w45IoaYfBcOLzp6vOgEJydg4wggR6MIIDYqADAgECAgphAbKbAAAA
# AAAVMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBMB4X
# DTExMDIyMTIwNTMxMloXDTEyMDUyMTIwNTMxMlowgYMxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxHjAcBgNVBAMTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKVxdBjL25wv+vFjGYCjjv/IcIMMoUcq+vpasM5ND7072iHNBdV9fD+1mXYl
# OtygTyDlctNDceb/bBT5n4SyJYe9FLVdvjeJLsWrhWBxhYEnuTMD+a3WkwLutlUR
# AsuDhfbBhWNhGaAUnJ2fnEZjN9gRPFfHSCBTFvfMWP72wBrKtkZsDeg6Bc6mHOOI
# 8N2qwnCDW9Hy8j+42aSdowBuqoHN7joErcBKkiwT4OlBdgmAAWxnILQxsD5r0kAI
# g9VwMI0w576M0C/u1IY/GlqlwGiF6Il8kQNKbllDIEiciP7JRbfoTAQBC2LOouwc
# kyX90LEOxvi2JBp7+3zWXE7RZ+kCAwEAAaOB+DCB9TATBgNVHSUEDDAKBggrBgEF
# BQcDAzAdBgNVHQ4EFgQU2XLUywxiX92jdJ9fDphBqFsTQyYwDgYDVR0PAQH/BAQD
# AgeAMB8GA1UdIwQYMBaAFMwdznYAcFuv8drETppRRC6jRGPwMEQGA1UdHwQ9MDsw
# OaA3oDWGM2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L0NTUENBLmNybDBIBggrBgEFBQcBAQQ8MDowOAYIKwYBBQUHMAKGLGh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvQ1NQQ0EuY3J0MA0GCSqGSIb3DQEB
# BQUAA4IBAQBgYCfYfDBJEkdBNzxedbTkogA2EUiwLFibmHztoxKhmO4Ys5f2bY7Y
# MBocrSFjQUaT168aKEuXNn1AVGDMYrzp/GmnX3/Fh6aGDHyp4ll924jVd3gFpiTK
# ZPhOUbdEKI4aLFQIKHLFHxg9LM8AJ28T0aVh8tZiOr0ATgUvmWd95WNDPzsMvosH
# euF4QL/feM6HIKIZobxg8J+sUlx2FP0beAXXY3Vrgf2HRq2tWVK/e7+vGaSSsvIL
# LH4wENsxS76EWn/3mxJ46d5+YKsNxjEe9nKaPmfPOO44zjkbc9s72TTfg9KczeGL
# 3hr+ZAhfr/YuuDIldmkl89WNNSPD2yVEMIIEnTCCA4WgAwIBAgIQaguZT8AAJasR
# 20UfWHpnojANBgkqhkiG9w0BAQUFADBwMSswKQYDVQQLEyJDb3B5cmlnaHQgKGMp
# IDE5OTcgTWljcm9zb2Z0IENvcnAuMR4wHAYDVQQLExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBSb290IEF1dGhvcml0eTAeFw0wNjA5
# MTYwMTA0NDdaFw0xOTA5MTUwNzAwMDBaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBUaW1lc3RhbXBpbmcg
# UENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3Ddu+6/IQkpxGMjO
# SD5TwPqrFLosMrsST1LIg+0+M9lJMZIotpFk4B9QhLrCS9F/Bfjvdb6Lx6jVrmlw
# ZngnZui2t++Fuc3uqv0SpAtZIikvz0DZVgQbdrVtZG1KVNvd8d6/n4PHgN9/TAI3
# lPXAnghWHmhHzdnAdlwvfbYlBLRWW2ocY/+AfDzu1QQlTTl3dAddwlzYhjcsdckO
# 6h45CXx2/p1sbnrg7D6Pl55xDl8qTxhiYDKe0oNOKyJcaEWL3i+EEFCy+bUajWzu
# JZsT+MsQ14UO9IJ2czbGlXqizGAG7AWwhjO3+JRbhEGEWIWUbrAfLEjMb5xD4Gro
# fyaOawIDAQABo4IBKDCCASQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwgaIGA1UdAQSB
# mjCBl4AQW9Bw72lyniNRfhSyTY7/y6FyMHAxKzApBgNVBAsTIkNvcHlyaWdodCAo
# YykgMTk5NyBNaWNyb3NvZnQgQ29ycC4xHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFJvb3QgQXV0aG9yaXR5gg8AwQCL
# PDyIEdE+9mPs30AwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFG/oTj+XuTSr
# S4aPvJzqrDtBQ8bQMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQCUTRExwnxQ
# uxGOoWEHAQ6McEWN73NUvT8JBS3/uFFThRztOZG3o1YL3oy2OxvR+6ynybexUSEb
# bwhpfmsDoiJG7Wy0bXwiuEbThPOND74HijbB637pcF1Fn5LSzM7djsDhvyrNfOzJ
# rjLVh7nLY8Q20Rghv3beO5qzG3OeIYjYtLQSVIz0nMJlSpooJpxgig87xxNleEi7
# z62DOk+wYljeMOnpOR3jifLaOYH5EyGMZIBjBgSW8poCQy97Roi6/wLZZflK3toD
# dJOzBW4MzJ3cKGF8SPEXnBEhOAIch6wGxZYyuOVAxlM9vamJ3uhmN430IpaczLB3
# VFE61nJEsiP2MIIEqjCCA5KgAwIBAgIKYQWiMAAAAAAACDANBgkqhkiG9w0BAQUF
# ADB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQD
# ExpNaWNyb3NvZnQgVGltZXN0YW1waW5nIFBDQTAeFw0wODA3MjUxOTAxMTVaFw0x
# MzA3MjUxOTExMTVaMIGzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMQ0wCwYDVQQLEwRNT1BSMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBFU046ODVE
# My0zMDVDLTVCQ0YxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwBC2ylsAagWclsSZi
# sxNLzjC6wBI4/IFlNAfENrIkaPYHBMAHl/S38XseYixG2UukUTS302ztWju0g6FH
# PREILjVrRebCPIwCZgKpGGnrSu0nLO48d1uk1HCZS1eEENCvLfiJHebqKbTnz54G
# YqdyVMI7xs8/uOGwWBBs5aXXw8J1N730heGB6CjYG/HyrvGCo9bXA6KfFYT7Pfqr
# 4bYyyKACZPPm/xomcQhTihUC8oMndkmCcafvrTJ4xtdsFk8iZZdiTUYv/yOvheym
# cL0Dy9rYMgXFK5BAtp7VLIZst8sTMn2Nxn6uFy8y/Ga7HbBFVfit+i1ng2cpk4TS
# WqEjAgMBAAGjgfgwgfUwHQYDVR0OBBYEFOiX9vfvjPHmaeNZaE73mIp63ZsuMB8G
# A1UdIwQYMBaAFG/oTj+XuTSrS4aPvJzqrDtBQ8bQMEQGA1UdHwQ9MDswOaA3oDWG
# M2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL3RzcGNh
# LmNybDBIBggrBgEFBQcBAQQ8MDowOAYIKwYBBQUHMAKGLGh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2kvY2VydHMvdHNwY2EuY3J0MBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIGwDANBgkqhkiG9w0BAQUFAAOCAQEADT93X5E8vqU1
# pNsFBYQfVvLvmabHCI0vs80/cdWGfHcf3esXsr184/mZ8gpFSK0Uu2ks8j5nYlTy
# 7n8nEZI57M7Zh06I92BHI3snFUAIn78NMQSC2DW2DJwA04uqeGHFtYhBnT423Fik
# J5s62r0GXRSmsg9MwY48i/Jimfhm7dXzHCiwMtvKMQm8+yJoRkz603Mi5ymOIgD7
# Vr8GroGgFbo0+SiOH0piBaGJ9YFH6Q2RCNdYO48eawlpqcBIfFWCP18AOEOcBsw/
# 2C+/T3MJPf26XvTH7DfCZGGgTdQ9cMxbsBOBwdSjMRq9ZNaW0no/KltGUwk8zQP5
# P1kAzIlTYTGCBHMwggRvAgEBMIGHMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENB
# AgphAbKbAAAAAAAVMAkGBSsOAwIaBQCggZ4wGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFBoCyBZ1TjPK5Jreg88o0P2iP4YwMD4GCisGAQQBgjcCAQwxMDAuoBaAFABX
# AGUAYgAgAEQAZQBwAGwAbwB5oRSAEmh0dHA6Ly93d3cuaWlzLm5ldDANBgkqhkiG
# 9w0BAQEFAASCAQBWIuqYLbCFr6e/NmtvF+b+cKCBW8JqS479RSCd7VWLKlvZb/wV
# WvKcMy/tz9iLZVIXZ/3wW0dSdn0YrqCYYgiPP8ZVa4YKyxw7j07G+D0QRCS3ZgPz
# Aw4DkaN1C7INavOnHrn5I5Fg3JFbU13Ba72iwfqXDL2IVP0jk34P5lBVaAedC9k0
# RUbDSwvEuiXIGIdviN/coHJv3GA3zXsfKuGDwNWcMRpp5ZPmUujusJXabaZVJ9q0
# QBOAPFrsbGvT3eSbKXHaERff1uc1znyRC3xZUqiYREOFT1UuzEQpX3ZeliWiKIon
# wbyZKx00RLPqUBeRzAi8sWpsJqzkGVwRO1iCoYICHzCCAhsGCSqGSIb3DQEJBjGC
# AgwwggIIAgEBMIGHMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xIzAhBgNVBAMTGk1pY3Jvc29mdCBUaW1lc3RhbXBpbmcgUENBAgphBaIwAAAA
# AAAIMAcGBSsOAwIaoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG
# 9w0BCQUxDxcNMTEwNDAyMDMxODA4WjAjBgkqhkiG9w0BCQQxFgQUu9WdM0Dniz8m
# cCONieilMw9twD8wDQYJKoZIhvcNAQEFBQAEggEAKA/EEQUTy0IU6tNNMUhXbt1u
# PJBrxNgxhtXXj1XFN+SKihG1Ms7bbqmmIOEIGPPglDoNRGgFFY/a4pdD6jlZ1pMP
# 3ulN8oI1wsKVEMtAgSP7kVgZloo4sak+9RHu3rnHN0KCNxP4jqAkEHfJDrJdqzoM
# wdXPn/4cWOwoxXuqLpScXHU8I1srwHc9GwLe6zbfWtGLa9Olz6iiKaC/mhD40v1t
# KIEgopqOMDsYXIoNn3iMVWm/RwCQLvYoJX5iK8DQTyVZhDXzk3wnKQ43a2YVaEPE
# rw5mUXoeF5LrICnxTMxtSAPdZNYH9WwzBGjpSjnHOfpsn5DT5txowdi5ejVTwg==
# SIG # End signature block
