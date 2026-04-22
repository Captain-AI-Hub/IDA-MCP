$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Mode = if ($args.Length -gt 0) { $args[0] } else { "standalone" }

if (-not (Test-Path $Python)) {
    throw "Python not found at $Python. Create a venv first: python -m venv $ProjectRoot\.venv"
}

# Forward any extra args (--no-debug, -j N) to the Python script
$ExtraArgs = @()
if ($args.Length -gt 1) {
    $ExtraArgs = $args[1..($args.Length - 1)]
}

& $Python "$PSScriptRoot\build_nuitka.py" --mode $Mode @ExtraArgs
