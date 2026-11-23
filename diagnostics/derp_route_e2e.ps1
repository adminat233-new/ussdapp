$ErrorActionPreference='Stop'
$exe='C:\Users\Admin\Documents\Default Project\ussdApp\Csharp\UssdApp.exe'
$profile='C:\Users\Admin\AppData\Local\Temp\opencode\derp_route_profile'
if (Test-Path $profile) { Remove-Item -Recurse -Force $profile }
New-Item -ItemType Directory -Path $profile | Out-Null
$proc=Start-Process -FilePath $exe -ArgumentList @("--home=`"$profile`"") -PassThru -RedirectStandardOutput "$profile\out.txt" -RedirectStandardError "$profile\err.txt"

function Read-Exact([System.Net.Sockets.NetworkStream]$s,[int]$n) {
  $b=New-Object byte[] $n
  $total=0
  while($total -lt $n){ $r=$s.Read($b,$total,$n-$total); if($r -le 0){ throw 'stream closed' }; $total+=$r }
  return ,$b
}
function Read-Frame([System.Net.Sockets.NetworkStream]$s) {
  $lb=Read-Exact $s 4
  $len=[System.Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($lb,0))
  if($len -le 0 -or $len -gt 65536){ throw "bad frame length $len" }
  $body=Read-Exact $s $len
  $payload=New-Object byte[] ($len-1)
  if($len -gt 1){ [Array]::Copy($body,1,$payload,0,$len-1) }
  return @{ Type=$body[0]; Payload=$payload }
}
function Send-Frame([System.Net.Sockets.NetworkStream]$s,[byte]$type,[byte[]]$payload) {
  if($null -eq $payload){ $payload=@() }
  $body=New-Object byte[] (1+$payload.Length)
  $body[0]=$type
  if($payload.Length -gt 0){ [Array]::Copy($payload,0,$body,1,$payload.Length) }
  $netlen=[System.Net.IPAddress]::HostToNetworkOrder([int]$body.Length)
  $lenbytes=[BitConverter]::GetBytes($netlen)
  $s.Write($lenbytes,0,4); $s.Write($body,0,$body.Length); $s.Flush()
}
function Register([string]$key) {
  $c=New-Object System.Net.Sockets.TcpClient('127.0.0.1',9005)
  $s=$c.GetStream(); $s.ReadTimeout=4000; $s.WriteTimeout=4000
  $magic=[Text.Encoding]::ASCII.GetBytes('DERP1'); $s.Write($magic,0,5); $s.Flush()
  $null=Read-Frame $s
  Send-Frame $s 1 ([Text.Encoding]::UTF8.GetBytes($key))
  $reply=Read-Frame $s
  if($reply.Type -ne 2){ throw "registration reply type $($reply.Type)" }
  $text=[Text.Encoding]::UTF8.GetString([byte[]]$reply.Payload)
  if(-not $text.StartsWith('OK|registered')){ throw "registration refused: $text" }
  return @{ Client=$c; Stream=$s; Key=$key }
}

try {
  $deadline=(Get-Date).AddSeconds(12)
  $up=$false
  while((Get-Date) -lt $deadline){
    try { $t=New-Object System.Net.Sockets.TcpClient('127.0.0.1',9005); $t.Close(); $up=$true; break } catch { Start-Sleep -Milliseconds 200 }
  }
  if(-not $up){ throw 'DERP router did not bind port 9005' }
  $a=Register 'alice'
  $b=Register 'bob'

  $dest=[Text.Encoding]::UTF8.GetBytes('bob')
  $cipher=[Text.Encoding]::UTF8.GetBytes('opaque-media-frame')
  $send=New-Object byte[] (1+$dest.Length+$cipher.Length)
  $send[0]=[byte]$dest.Length
  [Array]::Copy($dest,0,$send,1,$dest.Length)
  [Array]::Copy($cipher,0,$send,1+$dest.Length,$cipher.Length)
  Send-Frame $a.Stream 3 $send

  $got=Read-Frame $b.Stream
  if($got.Type -ne 4){ throw "delivery type $($got.Type), expected 4" }
  $p=[byte[]]$got.Payload
  $srcLen=[int]$p[0]
  $src=[Text.Encoding]::UTF8.GetString($p,1,$srcLen)
  $body=[Text.Encoding]::UTF8.GetString($p,1+$srcLen,$p.Length-$srcLen-1)
  if($src -ne 'alice'){ throw "source key $src" }
  if($body -ne 'opaque-media-frame'){ throw "payload $body" }

  'DERP ROUTE TEST: PASS'
  '  registered=alice,bob routed=1 payload=opaque'
}
finally {
  if($a){ try{$a.Client.Close()}catch{} }
  if($b){ try{$b.Client.Close()}catch{} }
  if($proc -and -not $proc.HasExited){ Stop-Process -Id $proc.Id -Force }
}
