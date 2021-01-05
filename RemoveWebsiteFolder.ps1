iisreset /stop
get-childitem ($pathToIIs + "*") -recurse | remove-item -Force -recurse
iisreset /start