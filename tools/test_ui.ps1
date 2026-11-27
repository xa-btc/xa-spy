# XA Spy isolated native UI fixture validation. Never targets an existing application.
param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$FixtureRoot,
    [string]$Screenshot = ''
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Executable).Path
$fixture = (Resolve-Path -LiteralPath $FixtureRoot).Path
if (-not (Test-Path -LiteralPath (Join-Path $fixture 'files') -PathType Container)) { throw 'Fixture files directory is required' }
if (Get-Process -Name XASpy -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe }) { throw 'Refusing to reuse an existing application path for UI validation' }

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class XASpyUiFixture {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr parameter);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc callback, IntPtr parameter);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr hwnd, StringBuilder text, int size);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr hwnd, int id);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hwnd, uint message, IntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
    public static extern IntPtr SendText(IntPtr hwnd, uint message, IntPtr w, StringBuilder text);
    [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll", EntryPoint="GetWindowLongW")] public static extern int GetStyle(IntPtr hwnd, int index);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out Rect rectangle);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] public static extern bool UpdateWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool RedrawWindow(IntPtr hwnd, IntPtr rectangle, IntPtr region, uint flags);
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    public static IntPtr Find(uint process, string name) {
        IntPtr result = IntPtr.Zero;
        EnumWindows(delegate(IntPtr hwnd, IntPtr unused) {
            uint pid; GetWindowThreadProcessId(hwnd, out pid);
            if (pid != process) return true;
            var text = new StringBuilder(256); GetClassName(hwnd, text, text.Capacity);
            if (text.ToString() == name) { result = hwnd; return false; }
            return true;
        }, IntPtr.Zero);
        return result;
    }
    public static string Text(IntPtr hwnd) {
        var text = new StringBuilder(8192);
        SendText(hwnd, 13, new IntPtr(text.Capacity), text);
        return text.ToString();
    }
}
'@
function Require([bool]$condition, [string]$description) {
    if (-not $condition) { throw ('FAIL: ' + $description) }
    Write-Output ('PASS: ' + $description)
}
function Wait-Terminal([IntPtr]$window, $process) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        if ($process.HasExited) { throw 'Fixture UI exited unexpectedly' }
        $text = [XASpyUiFixture]::Text([XASpyUiFixture]::GetDlgItem($window, 109))
        if (($text -match '^State: (completed|cancelled|failed)') -and
            [XASpyUiFixture]::IsWindowEnabled([XASpyUiFixture]::GetDlgItem($window, 103))) { return $text }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Fixture scan did not reach a terminal UI state in 30 seconds'
}
function Command([IntPtr]$window, [int]$id) {
    [void][XASpyUiFixture]::SendMessage($window, 0x0111, [IntPtr]$id, [XASpyUiFixture]::GetDlgItem($window, $id))
}

$process = Start-Process -FilePath $exe -ArgumentList @('--fixture-ui', ('"' + $fixture + '"')) -WindowStyle Hidden -PassThru
$window = [IntPtr]::Zero
$cancelDirectory = $null
$cancelFile = $null
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        if ($process.HasExited) { throw 'Fixture UI failed to start' }
        $window = [XASpyUiFixture]::Find($process.Id, 'XASpyNative')
        if ($window -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    Require ($window -ne [IntPtr]::Zero) 'isolated fixture window created'
    Require ([XASpyUiFixture]::Text($window) -match 'Synthetic Fixture') 'fixture identity is visible'
    $mode = [XASpyUiFixture]::GetDlgItem($window, 106)
    Require ([XASpyUiFixture]::SendMessage($mode, 0x0147, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64() -eq 0) 'Local System Audit is default'
    $target = [XASpyUiFixture]::GetDlgItem($window, 101)
    Require (([XASpyUiFixture]::GetStyle($target, -16) -band 0x10000000) -eq 0) 'system audit does not require folder UI'
    Require ([XASpyUiFixture]::SendMessage([XASpyUiFixture]::GetDlgItem($window, 105), 0x00F0, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64() -eq 0) 'browser checks are opt-in'
    Require (-not [XASpyUiFixture]::IsWindowEnabled([XASpyUiFixture]::GetDlgItem($window, 108))) 'private report remains closed before explicit scan'
    $settings = [XASpyUiFixture]::GetDlgItem($window, 112)
    Require ([XASpyUiFixture]::SendMessage($settings, 0x00F0, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64() -eq 0) 'security settings are opt-in'
    [void][XASpyUiFixture]::SendMessage($settings, 0x00F1, [IntPtr]1, [IntPtr]::Zero)
    Command $window 103
    $state = Wait-Terminal $window $process
    Require ($state -match '^State: completed') 'synthetic system audit completes through Start'
    $rows = [XASpyUiFixture]::SendMessage([XASpyUiFixture]::GetDlgItem($window, 107), 0x1004, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
    Require ($rows -ge 11) 'per-check results are populated'
    Require ([XASpyUiFixture]::IsWindowEnabled([XASpyUiFixture]::GetDlgItem($window, 108))) 'local report becomes available after run'
    if ($Screenshot) {
        $destination = [System.IO.Path]::GetFullPath($Screenshot)
        $directory = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $directory)) { throw 'Screenshot destination directory must already exist' }
        [uint32]$ownerId = 0
        [void][XASpyUiFixture]::GetWindowThreadProcessId($window, [ref]$ownerId)
        Require ($ownerId -eq $process.Id -and -not $process.HasExited) 'screenshot targets only the owned fixture window'
        $bitmap = $null
        $graphics = $null
        try {
            # Hidden windows can return a successful but all-black PrintWindow result.
            # Show this owned fixture without activation; never capture the desktop or other windows.
            [void][XASpyUiFixture]::ShowWindow($window, 4) # SW_SHOWNOACTIVATE
            [void][XASpyUiFixture]::RedrawWindow($window, [IntPtr]::Zero, [IntPtr]::Zero, 0x0585)
            [void][XASpyUiFixture]::UpdateWindow($window)
            Start-Sleep -Milliseconds 150
            $rect = New-Object XASpyUiFixture+Rect
            Require ([XASpyUiFixture]::GetWindowRect($window, [ref]$rect)) 'owned fixture dimensions are available'
            $bitmap = New-Object System.Drawing.Bitmap(($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top))
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $dc = $graphics.GetHdc()
            try { Require ([XASpyUiFixture]::PrintWindow($window, $dc, 2)) 'owned window screenshot captured' }
            finally { $graphics.ReleaseHdc($dc) }
            $colors = New-Object 'System.Collections.Generic.HashSet[int]'
            $nonBlack = 0
            $samples = 0
            $stepX = [Math]::Max(1, [int]($bitmap.Width / 64))
            $stepY = [Math]::Max(1, [int]($bitmap.Height / 64))
            for ($y = 10; $y -lt $bitmap.Height - 10; $y += $stepY) {
                for ($x = 10; $x -lt $bitmap.Width - 10; $x += $stepX) {
                    $pixel = $bitmap.GetPixel($x, $y)
                    [void]$colors.Add($pixel.ToArgb())
                    if ($pixel.R -gt 8 -or $pixel.G -gt 8 -or $pixel.B -gt 8) { $nonBlack++ }
                    $samples++
                }
            }
            Require ($samples -gt 0 -and $nonBlack -gt ($samples / 4) -and $colors.Count -ge 4) 'screenshot contains rendered content rather than a blank/black image'
            $bitmap.Save($destination, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally {
            [void][XASpyUiFixture]::ShowWindow($window, 0) # SW_HIDE
            if ($graphics) { $graphics.Dispose() }
            if ($bitmap) { $bitmap.Dispose() }
        }
    }
    Command $window 111
    $review = [XASpyUiFixture]::Find($process.Id, 'XASpyLocalReport')
    $reviewText = [XASpyUiFixture]::Text([XASpyUiFixture]::GetDlgItem($review, 201))
    Require ($reviewText.Contains('Next step:') -and $reviewText.Contains('WINDOWS SECURITY SETTINGS')) 'local review shows guidance and optional settings'
    [void][XASpyUiFixture]::SendMessage($review, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    Command $window 108
    $report = [XASpyUiFixture]::Find($process.Id, 'XASpyLocalReport')
    Require ($report -ne [IntPtr]::Zero) 'private report opens only on explicit click'
    $reportText = [XASpyUiFixture]::Text([XASpyUiFixture]::GetDlgItem($report, 201))
    Require ($reportText.StartsWith('LOCAL PRIVATE EVIDENCE')) 'native report viewer marks evidence private and untrusted'
    [void][XASpyUiFixture]::SendMessage($report, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    [void][XASpyUiFixture]::SendMessage($mode, 0x014E, [IntPtr]1, [IntPtr]::Zero)
    [void][XASpyUiFixture]::SendMessage($window, 0x0111, [IntPtr](106 -bor (1 -shl 16)), $mode)
    Require (([XASpyUiFixture]::GetStyle($target, -16) -band 0x10000000) -ne 0) 'targeted mode exposes selected folder'
    # A new, owned synthetic file prevents an empty/instant folder scan from winning the cancel race.
    $cancelDirectory = Join-Path (Join-Path $fixture 'files') ('ui-cancel-' + [Guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($cancelDirectory)
    $cancelFile = Join-Path $cancelDirectory 'synthetic.exe'
    $stream = [System.IO.File]::Open($cancelFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
    try { $stream.SetLength(64 * 1024 * 1024) } finally { $stream.Dispose() }
    [void][XASpyUiFixture]::SendText($target, 0x000C, [IntPtr]::Zero, (New-Object System.Text.StringBuilder($cancelDirectory)))
    Command $window 103
    Command $window 104
    $state = Wait-Terminal $window $process
    Require ($state -match '^State: cancelled') 'Cancel reaches a cancelled result in fixture scope'
    [void][XASpyUiFixture]::SendMessage($window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    Require ($process.WaitForExit(10000)) 'owned fixture UI closes gracefully'
} finally {
    if (-not $process.HasExited -and $window -ne [IntPtr]::Zero) {
        [void][XASpyUiFixture]::SendMessage($window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
        [void]$process.WaitForExit(10000)
    }
    if ($process.HasExited -and $cancelFile -and (Test-Path -LiteralPath $cancelFile)) {
        Remove-Item -LiteralPath $cancelFile
        if ($cancelDirectory) { Remove-Item -LiteralPath $cancelDirectory }
    }
    $process.Dispose()
}
