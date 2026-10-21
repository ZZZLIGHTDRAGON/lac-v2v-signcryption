$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceDir = Join-Path $projectRoot "LAC\Additional_Implementation"
$buildDir = "C:\lac_build\Additional_Implementation"
$msysBash = "C:\msys64\usr\bin\bash.exe"
$libcrypto = "C:\msys64\ucrt64\bin\libcrypto-3-x64.dll"

if (-not (Test-Path $msysBash)) {
    throw "未找到 MSYS2 bash：$msysBash"
}

if (-not (Test-Path $sourceDir)) {
    throw "未找到源码目录：$sourceDir"
}

New-Item -ItemType Directory -Force $buildDir | Out-Null
Copy-Item (Join-Path $sourceDir "*") $buildDir -Recurse -Force

$compileScript = @"
export PATH=/ucrt64/bin:`$PATH
cd /c/lac_build/Additional_Implementation
gcc -shared -O3 -Wall -DNDEBUG -mavx2 -Dhtobe32=__builtin_bswap32 -I/ucrt64/include -L/ucrt64/lib -o lac_bridge.dll lac_bridge.c encrypt.c kem.c ecc.c bch.c bin-lwe.c rand.c rng.c -lcrypto
"@

$env:MSYSTEM = "UCRT64"
$env:CHERE_INVOKING = "1"
& $msysBash --login -lc $compileScript
if ($LASTEXITCODE -ne 0) {
    throw "lac_bridge.dll 编译失败，退出码：$LASTEXITCODE"
}

Copy-Item (Join-Path $buildDir "lac_bridge.dll") (Join-Path $sourceDir "lac_bridge.dll") -Force
Copy-Item $libcrypto (Join-Path $sourceDir "libcrypto-3-x64.dll") -Force

Write-Host "lac_bridge.dll 已生成并复制到 $sourceDir"
