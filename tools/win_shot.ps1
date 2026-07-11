# win_shot.ps1 — capture a single named top-level window to PNG (no full-desktop, no personal content).
# Deterministic evidence-screenshot primitive for verified bug-bounty submissions.
# Finds the visible window whose title contains -Title (works even for multi-window/tabbed apps
# where MainWindowTitle only exposes one), brings it forward, and saves just that window.
#
# Usage (from the PowerShell tool):
#   powershell -File tools\win_shot.ps1 -Title "IK-SSRF-OOB" -Out "\\wsl.localhost\kali-linux\home\d0k\...\shot.png"
param([Parameter(Mandatory=$true)][string]$Title, [Parameter(Mandatory=$true)][string]$Out)
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class WinShot {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc e, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int m);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  public static IntPtr Find(string t){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ if(!IsWindowVisible(h))return true; var sb=new StringBuilder(512); GetWindowText(h,sb,512); if(sb.ToString().Contains(t)){f=h;return false;} return true;}, IntPtr.Zero); return f; }
}
"@
[WinShot]::SetProcessDPIAware() | Out-Null
$h = [WinShot]::Find($Title)
if ($h -eq [IntPtr]::Zero) { Write-Output "WINDOW NOT FOUND: $Title"; exit 1 }
[WinShot]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 800
$r = New-Object WinShot+RECT
[WinShot]::GetWindowRect($h, [ref]$r) | Out-Null
$w = $r.Right - $r.Left; $ht = $r.Bottom - $r.Top
if ($w -le 0 -or $ht -le 0) { Write-Output "BAD RECT"; exit 1 }
$bmp = New-Object System.Drawing.Bitmap $w, $ht
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output "SAVED $Out (${w}x${ht})"
