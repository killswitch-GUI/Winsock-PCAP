param ($ComputerName = '.')
 
$npipeClient = new-object System.IO.Pipes.NamedPipeClientStream(
 $ComputerName, 'my_pipe', 
 [System.IO.Pipes.PipeDirection]::InOut,
 [System.IO.Pipes.PipeOptions]::None, 
 [System.Security.Principal.TokenImpersonationLevel]::Impersonation
 )
 
$pipeReader = $pipeWriter = $null
try {
    $npipeClient.Connect()
    $pipeReader = new-object System.IO.StreamReader($npipeClient)
    $pipeWriter = new-object System.IO.StreamWriter($npipeClient)
    $pipeWriter.AutoFlush = $true
    # Connect Loop
    while (1) {
        write-host "[*] Server Sent: " $pipeReader.ReadLine()
        $User = Read-Host -Prompt 'Send code to server: '
        $pipeWriter.Write($User)
    }
}
finally {
    'Time to exit pipe: '
    $npipeClient.Dispose()
}
