IIS:\>New-WebAppPool MyNewAppPool "Sleep for 5 seconds before AppPool gets removed"; Sleep 5 Remove-WebAppPool MyNewAppPool