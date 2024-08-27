import ctypes
import os
import platform
import psutil # type: ignore

from main import error_handler

async def check_for_suspicious_files(self) -> None:
    try:
        temp_file_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Temp', 'JSAMSIProvider64.dll')
        if os.path.exists(temp_file_path):
            ctypes.windll.kernel32.ExitProcess(0)
        try:
            machine_name = platform.uname().machine.lower()
            if "dady harddisk" in machine_name or "qemu harddisk" in machine_name:
                ctypes.windll.kernel32.ExitProcess(0)
        except AttributeError:
            pass

        suspicious_process_names = ["32dbg", "64dbgx", "autoruns", "autoruns64", "autorunsc", "autorunsc64", "ciscodump", "df5serv", "die", "dumpcap", "efsdump", "etwdump", "fakenet", "fiddler", "filemon", "hookexplorer", "httpdebugger", "httpdebuggerui", "ida", "ida64", "idag", "idag64", "idaq", "idaq64", "idau", "idau64", "idaw", "immunitydebugger", "importrec", "joeboxcontrol", "joeboxserver", "ksdumperclient", "lordpe", "ollydbg", "pestudio", "petools", "portmon", "prl_cc", "prl_tools", "proc_analyzer", "processhacker", "procexp", "procexp64", "procmon", "procmon64", "qemu-ga", "qga", "regmon", "reshacker", "resourcehacker", "sandman", "sbiesvc", "scylla", "scylla_x64", "scylla_x86", "sniff_hit", "sysanalyzer", "sysinspector", "sysmon", "tcpdump", "tcpview", "tcpview64", "udpdump", "vboxcontrol", "vboxservice", "vboxtray", "vgauthservice", "vm3dservice", "vmacthlp", "vmsrvc", "vmtoolsd", "vmusrvc", "vmwaretray", "vmwareuser", "vt-windows-event-stream", "windbg", "wireshark", "x32dbg", "x64dbg", "x96dbg", "xenservice"]
        
        running_processes = [
            process.name().lower() for process in psutil.process_iter(attrs=['name']) 
            if process.name().lower() in suspicious_process_names
        ]
        if running_processes:
            ctypes.windll.kernel32.ExitProcess(0)
    except Exception as e:
        error_handler(f"sus files error - {str(e)}")
