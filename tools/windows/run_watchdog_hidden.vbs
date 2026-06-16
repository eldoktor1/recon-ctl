' run_watchdog_hidden.vbs -- launch the WSL VPN watchdog with NO visible window.
' A scheduled task that exec's powershell.exe directly flashes a console window
' every run (conhost spawns before -WindowStyle Hidden applies). wscript has no
' console of its own and Run(cmd, 0, False) starts powershell with SW_HIDE from
' the outset -> zero flash. The task stays in the user's interactive session, so
' WSLg/session semantics are unchanged; only the window is gone.
Dim sh, ps
Set sh = CreateObject("WScript.Shell")
ps = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""C:\Users\mhabs\recon-watchdog\wsl_vpn_watchdog.ps1"""
sh.Run ps, 0, False
