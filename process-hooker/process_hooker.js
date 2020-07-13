// Enable Debugging
var DEBUG_FLAG = true;

// Allow Shell commands
var ALLOW_SHELL = false;

// Allow DNS Requests
var DISABLE_DNS = false;

// Allow WSASend
var DISABLE_WSASEND = true;

// Allow COM Object lookup
var DISABLE_COM_INIT = true;

recv('set_script_vars', function onMessage(setting) {

    debug("Setting Script Vars...")
    DEBUG_FLAG = setting['debug'];
    debug(" - DEBUG_FLAG: " +  DEBUG_FLAG);
    DISABLE_DNS = setting['disable_dns'];
    debug(" - DISABLE_DNS: " +  DISABLE_DNS);
    ALLOW_SHELL = setting['allow_shell'];
    debug(" - ALLOW_SHELL: " +  DISABLE_DNS);
    DISABLE_WSASEND = setting['disable_send'];
    debug(" - DISABLE_WSASEND: " +  DISABLE_WSASEND);
    DISABLE_COM_INIT = setting['disable_com'];
    debug(" - DISABLE_COM_INIT: " +  DISABLE_COM_INIT);

});

function debug(msg)
{
    if(DEBUG_FLAG == true){
        send({
            name: 'log',
            payload: msg
        });
        recv('ack', function () {}).wait();
    }
}

function log_instr(msg){
    send({
        name: 'instr',
        hookdata: msg
    });
}

var ADDRESS_FAMILY = {}
ADDRESS_FAMILY[0x0] = "AF_UNSPEC";
ADDRESS_FAMILY[0x2] = "AF_INET";
ADDRESS_FAMILY[0X6] = "AF_IPX";
ADDRESS_FAMILY[0X16] = "AF_APPLETALK";
ADDRESS_FAMILY[0X17] = "AF_NETBIOS";
ADDRESS_FAMILY[0X23] = "AF_INET6";
ADDRESS_FAMILY[0X26] = "AF_IRDA";
ADDRESS_FAMILY[0X32] = "AF_BTH";

//https://msdn.microsoft.com/en-us/library/windows/desktop/dd542643(v=vs.85).aspx

var CO_E_CLASSSTRING = 0x800401F3;
var REGDB_E_WRITEREGDB = 0x80040151;
var S_OK = 0;


/*
HRESULT CLSIDFromProgID(
  _In_  LPCOLESTR lpszProgID,
  _Out_ LPCLSID   lpclsid
);
 */
var ptrCLSIDFromProgID = Module.findExportByName("Ole32.dll", "CLSIDFromProgID");
var CLSIDFromProgID = new NativeFunction(ptrCLSIDFromProgID, 'uint', ['pointer', 'pointer']);
Interceptor.replace(ptrCLSIDFromProgID, new NativeCallback(function (lpszProgID, lpclsid) {
     var retval = CO_E_CLASSSTRING;

     var prog_id = lpszProgID.readUtf16String();
     log_instr({'hook':'clsid','progid': prog_id});

     if(!DISABLE_COM_INIT){
         retval = CLSIDFromProgID(lpszProgID, lpclsid);
    }
    return retval;
 },'uint',['pointer', 'pointer']));

var ptrWSASocketW = Module.findExportByName("WS2_32.DLL", "WSASocketW");
Interceptor.attach(ptrWSASocketW, {
    onEnter: function (args) {
        debug(" WSASocketW() Called");
        debug("   |-- Address Family: " + ADDRESS_FAMILY[parseInt(args[0],16)]+"["+ args[0]+"]");
    },
    onLeave: function (retval) {
        //console.log("Leave");
        if (retval.toInt32() > 0) {
            /* do something with this.fileDescriptor */
        }
    }
});

var NAMESPACE = {
    0:"NS_ALL",
    12:"NS_DNS",
    13:"NS_NETBT",
    14:"NS_WINS",
    15:"NS_NLA",
    16:"NS_BTH",
    32:"NS_NTDS",
    37:"NS_EMAIL",
    38:"NS_PNRPNAME",
    39:"NS_PNRPCLOUD"
};

var WSAHOST_NOT_FOUND = 11001;
/*
int WSAAPI GetAddrInfoEx(
  _In_opt_        PCTSTR                             pName,
  _In_opt_        PCTSTR                             pServiceName,
  _In_            DWORD                              dwNameSpace,
  _In_opt_        LPGUID                             lpNspId,
  _In_opt_  const ADDRINFOEX                         *pHints,
  _Out_           PADDRINFOEX                        *ppResult,
  _In_opt_        struct timeval                     *timeout,
  _In_opt_        LPOVERLAPPED                       lpOverlapped,
  _In_opt_        LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
  _Out_opt_       LPHANDLE                           lpNameHandle
);
 */
var ptrGetAddrInfoExW = Module.findExportByName("WS2_32.DLL", "GetAddrInfoExW");
var GetAddrInfoExW = new NativeFunction(ptrGetAddrInfoExW, 'int', ['pointer', 'pointer', 'uint', 'pointer','pointer','pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
Interceptor.replace(ptrGetAddrInfoExW, new NativeCallback(function (pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle) {
    //Set the default return to not found
    var retval = WSAHOST_NOT_FOUND;
    if(!DISABLE_DNS) retval = GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
      if(dwNameSpace = 0x12){
            var host =  pName.readUtf16String();
            log_instr({'hook':'dns','host': host});
        }
        else{
            debug(" AddrInfo Request: " + NAMESPACE[dwNameSpace] +"[" + dwNameSpace + "]");
        }
    return retval;


},'int', ['pointer', 'pointer', 'uint', 'pointer','pointer','pointer', 'pointer', 'pointer', 'pointer', 'pointer']));



/*
https://msdn.microsoft.com/en-us/library/windows/desktop/ms742203(v=vs.85).aspx
int WSASend(
  _In_  SOCKET                             s,
  _In_  LPWSABUF                           lpBuffers,
  _In_  DWORD                              dwBufferCount,
  _Out_ LPDWORD                            lpNumberOfBytesSent,
  _In_  DWORD                              dwFlags,
  _In_  LPWSAOVERLAPPED                    lpOverlapped,
  _In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine

https://msdn.microsoft.com/en-us/library/windows/desktop/ms741542(v=vs.85).aspx

  typedef struct __WSABUF {
  u_long   len;
  char FAR *buf;
} WSABUF, *LPWSABUF;

);
 */
var buffer = 0;
var ptrWSASend = Module.findExportByName("WS2_32.DLL", "WSASend");
var WSASend = new NativeFunction(ptrWSASend, 'int', ['pointer', 'pointer', 'uint', 'pointer','uint','pointer', 'pointer']);
Interceptor.replace(ptrWSASend, new NativeCallback(function (s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine) {
    var retval = 10060;
	
    if(!DISABLE_WSASEND){
        retval = WSASend(s, lpBuffers, dwBufferCount,lpNumberOfBytesSent,dwFlags,lpOverlapped,lpCompletionRoutine);
    }
    else{
        // TODO: Force the socket closed
        // Passing an error as a return value makes cscript cry and try try again..
        // for now capture the lpbuffer value and if we've see it just nop out
        //
        //
        if(buffer == lpBuffers){
            return retval;
        }
        buffer = lpBuffers;
    }
	
    //TODO: Handle multiple wsabuff structures..for now we assume that there is only one.
    //      But these could be chained in an array of [WSABUF, WSABUF, WSABUF, WSABUF]
    //
    debug("----------------------");
    debug("   |-- Socket ("+s+")");
    debug("   |-- LPWSABUF ("+lpBuffers+")");
    debug("   |-- Buffers " + dwBufferCount);
	
	var buff_len = lpBuffers.readULong();
    debug("   |-- Buffer Len " + buff_len);
	var far = lpBuffers.add(Process.pointerSize).readPointer();
    debug("   |-- FAR " + far);

/*  	var buf = ptr(lpBuffers).readByteArray(16);
	debug("   |--- " + hexdump(buf, {
									 offset: 0, 
									 length: 16,
									 header: true,
									 ansi: false
									})); */

    var request_data = far.readCString(buff_len);
    try {
        debug("-- Request Data --");
        debug(request_data);
        debug("-- Request Data End --");
        log_instr({"hook":'wsasend', "request": request_data, "buffers": dwBufferCount});
    }
    catch(err){}

    return retval

},'int',['pointer', 'pointer', 'uint', 'pointer','uint','pointer', 'pointer']));


//WSASendTo
var ptrWSASendTo = Module.findExportByName("WS2_32.DLL", "WSASendTo");
Interceptor.attach(ptrWSASendTo, {
    onEnter: function (args) {
        debug(" WSASendTo() Called");
    },
    onLeave: function (retval) {
    }
});


var ptrWSAAddressToStringW = Module.findExportByName("WS2_32.DLL", "WSAAddressToStringW");
Interceptor.attach(ptrWSAAddressToStringW, {
    onEnter: function (args) {
        debug(" WSAAddressToStringW() Called");
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            /* do something with this.fileDescriptor */
        }
    }
});


var ptrWSAStartup = Module.findExportByName("WS2_32.DLL", "WSAStartup");
Interceptor.attach(ptrWSAStartup, {
    onEnter: function (args) {
        debug(" WSAStartup() Called");
        debug("   |-- Requesting Version ("+ args[0]+")");
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            // nop
        }
    }
});

// https://msdn.microsoft.com/en-us/library/windows/desktop/bb762153(v=vs.85).aspx
var SHOWCMD = {
    0:"SW_HIDE",
    1:"SW_SHOWNORMAL",
    2:"SW_SHOWMINIMIZED",
    3:"SW_SHOWMAXIMIZED",
    4:"SW_SHOWNOACTIVATE",
    5:"SW_SHOW",
    6:"SW_MINIMIZE",
    7:"SW_SHOWMINNOACTIVE",
    8:"SW_SHOWNA",
    9:"SW_RESTORE",
    10:"SW_SHOWDEFAULT"
};

var ptrShellExecute = Module.findExportByName("Shell32.dll", "ShellExecuteExW");
var ShellExecute = new NativeFunction(ptrShellExecute, 'int', ['pointer']);
Interceptor.replace(ptrShellExecute, new NativeCallback(function (executeinfo) {

        var retval = false;

        //To pass the shell instruction comment out this line..
        if(ALLOW_SHELL == true)retval = ShellExecute(executeinfo);

        var shellinfo_ptr = executeinfo;
        var structure_size = shellinfo_ptr.readUInt();
        var ptr_file = shellinfo_ptr.add(16).readPointer();
        var ptr_params = shellinfo_ptr.add(20).readPointer();
        var nshow = shellinfo_ptr.add(28).readPointer();

        var lpfile = ptr(ptr_file).readUtf16String();
        var lpparams = ptr(ptr_params).readUtf16String();

        log_instr({"hook":'shell', "nshow": SHOWCMD[nshow], "cmd": lpfile, "params": lpparams});

        return retval;
},'int',['pointer']));


// IsDebuggerPresent
var ptrIsDebuggerPresent = Module.findExportByName("Kernel32.dll", "IsDebuggerPresent");
var IsDebuggerPresent = new NativeFunction(ptrIsDebuggerPresent, 'int', ['int']);
Interceptor.replace(ptrIsDebuggerPresent, new NativeCallback(function (executeinfo) {
	debug(" IsDebuggerPresent() Called");
        debug("   |-- Returning 0");
        log_instr({"hook":'debugger'});
        return 0;
},'int',['int']));


// OutputDebugStringW
var ptrOutputDebugStringW = Module.findExportByName("Kernel32.DLL", "OutputDebugStringW");
Interceptor.attach(ptrOutputDebugStringW, {
    onEnter: function (args) {
        debug(" OutputDebugStringW() Called");
        debug("   |-- Process ("+ args[0].readAnsiString()+")");
    },
    onLeave: function (retval) {
    }
});

// OutputDebugStringA
var ptrOutputDebugStringA = Module.findExportByName("Kernel32.DLL", "OutputDebugStringA");
Interceptor.attach(ptrOutputDebugStringA, {
    onEnter: function (args) {
        debug(" OutputDebugStringA() Called");
        debug("   |-- Process ("+ args[0].readAnsiString()+")");
    },
    onLeave: function (retval) {
    }
});

var ptrCreateProcessA = Module.findExportByName("Kernel32.DLL", "CreateProcessA");
Interceptor.attach(ptrCreateProcessA, {
    onEnter: function (args) {
        debug(" CreateProcessA() Called");
        debug("   |-- Process ("+ args[0].readAnsiString()+" "+args[1].readAnsiString()+")");
    },
    onLeave: function (retval) {
    }
});

// WinHttpConnect
var ptrWinHttpConnect = Module.findExportByName("Winhttp.dll", "WinHttpConnect");
Interceptor.attach(ptrWinHttpConnect, {
    onEnter: function (args) {
        debug(" WinHttpConnect() Called");
        debug("   |-- Process ("+ args[1].readAnsiString()+":"+args[2]+")");
    },
    onLeave: function (retval) {
    }
});

// HttpOpenRequestW
var ptrHttpOpenRequestW = Module.findExportByName("Wininet.dll", "HttpOpenRequestW");
Interceptor.attach(ptrHttpOpenRequestW, {
    onEnter: function (args) {
        debug(" HttpOpenRequestW() Called");
        debug("   |-- Process ("+args[1].readAnsiString()+" "+args[2].readAnsiString()+args[3].readAnsiString()+" "+args[4].readAnsiString()+")");
    },
    onLeave: function (retval) {
    }
});

// FtpOpenFileW
var ptrFtpOpenFileW = Module.findExportByName("Wininet.dll", "FtpOpenFileW");
Interceptor.attach(ptrFtpOpenFileW, {
    onEnter: function (args) {
        debug(" FtpOpenFileW() Called");
        debug("   |-- Process ("+ args[1].readAnsiString()+")");
    },
    onLeave: function (retval) {
    }
});

//FtpPutFileW
var ptrFtpPutFileW = Module.findExportByName("Wininet.dll", "FtpPutFileW");
Interceptor.attach(ptrFtpPutFileW, {
    onEnter: function (args) {
        debug(" FtpPutFileW() Called");
        debug("   |-- Process ("+args[1].readAnsiString()+" -> "+args[2].readAnsiString()+")");
    },
    onLeave: function (retval) {
    }
});

// GetCommandLineA
// GetCommandLineW
// LoadLibraryA
// GetModuleHandleA
// GetModuleHandleW
// GetModuleFileNameW
// GetModuleHandleExW
// GetModuleFileNameA
// VkKeyScanA
// EnumClipboardFormats
// GetVersionExW
// MoveFileExW
// FindNextFileW
// FindFirstFileW
// DeleteFileW
// FindFirstFileExA

// FindNextFileA
var ptrFtpPutFileW = Module.findExportByName("Wininet.dll", "FtpPutFileW");
Interceptor.attach(ptrFtpPutFileW, {
    onEnter: function (args) {
        debug(" FtpPutFileW() Called");
        debug("   |-- Process ("+args[1].readAnsiString()+" -> "+args[2].readAnsiString()+")");
    },
    onLeave: function (retval) {
    }
});

// TerminateProcess
var ptrTerminateProcess = Module.findExportByName("Kernel32.dll", "TerminateProcess");
Interceptor.attach(ptrTerminateProcess, {
    onEnter: function (args) {
        debug(" TerminateProcess() Called");
        debug("   |-- Process Terminating");
    },
    onLeave: function (retval) {
    }
});

// GetCurrentProcessId
var ptrGetCurrentProcessId = Module.findExportByName("Kernel32.dll", "GetCurrentProcessId");
Interceptor.attach(ptrGetCurrentProcessId, {
    onEnter: function (args) {
        debug(" GetCurrentProcessId() Called");
    },
    onLeave: function (retval) {
    }
});

// GetCurrentThreadId
var ptrGetCurrentThreadId = Module.findExportByName("Kernel32.dll", "GetCurrentThreadId");
Interceptor.attach(ptrGetCurrentThreadId, {
    onEnter: function (args) {
        debug(" GetCurrentThreadId() Called");
    },
    onLeave: function (retval) {
    }
});

// GetExitCodeProcess
var ptrGetExitCodeProcess = Module.findExportByName("Kernel32.dll", "GetExitCodeProcess");
Interceptor.attach(ptrGetExitCodeProcess, {
    onEnter: function (args) {
        debug(" GetExitCodeProcess() Called");
        debug("   |-- Exit Code ("+args[1].readInt()+")");
    },
    onLeave: function (retval) {
    }
});

// CreateProcessA
var ptrCreateProcessA = Module.findExportByName("Kernel32.dll", "CreateProcessA");
Interceptor.attach(ptrFtpPutFileW, {
    onEnter: function (args) {
        debug(" FtpPutFileW() Called");
        debug("   |-- Process ("+args[0].readAnsiString()+" "+args[1].readAnsiString()+")");
    },
    onLeave: function (retval) {
	}
});

// GetEnvironmentStringsW
// SetEnvironmentVariableA
// WinHttpSendRequest
// WinHttpReceiveResponse
// WinHttpQueryDataAvailable
// WinHttpCloseHandle
// WinHttpReadData
// WinHttpOpen
// WinHttpOpenRequest
// InternetConnectW
// InternetOpenW
// InternetCloseHandle
// InternetGetLastResponseInfoW
// InternetConnectA
// InternetQueryOptionW
// InternetSetOptionW
// HttpSendRequestW
// HttpQueryInfoW


// "ADVAPI32.CryptHashData", "ADVAPI32.CryptEncrypt"]
