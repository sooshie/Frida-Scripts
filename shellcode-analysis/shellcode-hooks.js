// CreateThread
var TID = 0
var ptrCreateThread = Module.findExportByName("Kernel32.dll", "CreateThread");
Interceptor.attach(ptrCreateThread, {
    onEnter: function (args) {
        console.log(" CreateThread() Called");
		this.tid = args[5];
    },
    onLeave: function (retval) {
		TID = this.tid.readInt();
		console.log("   |-- Thread ID " + TID);
		console.log("   |-- Handle " + retval);
	}
});

// ResumeThread
var found_at = -1
var ptrResumeThread = Module.findExportByName("Kernel32.dll", "ResumeThread");
Interceptor.attach(ptrResumeThread, {
    onEnter: function (args) {
        console.log(" ResumeThread() Called");
		console.log("    | -- Following Thread ID " + TID);

		/* Trace the thread with Stalker */
		Stalker.follow(TID, {
			events: { call: true, ret: false, exec: true, block: false, compile: true },

			onReceive: function(events) {
				console.log(events);
				if (found_at != -1) return;
				events = Stalker.parse(events);

				console.log(events);
				console.log(events.length);
				for (var i = 0; i < events.length; i++) {
					//const ev = events[i];
					console.log(i);
					console.log(events[i].length);
					console.log(events[i]);

/* 					const symbol = DebugSymbol.fromAddress(target);
					console.log("here");

					console.log(target);
					console.log(symbol.name);
*/
					  /* This code will highlight the fileExists call in the stack */
/*
					  if (!!symbol && !!symbol.name && (symbol.name.indexOf('WinExec') >= 0)) {
						console.warn('WinExec');
						found_at = i;
						break;
					  } */
					  
					  /* This code will display a frame that belongs to our module */
					  /* if (!!symbol && !!symbol.moduleName && !!symbol.name &&
						  (symbol.moduleName.indexOf('blog-1-storyboard') >= 0) && 
						  (symbol.name.indexOf('DYLD-STUB') < 0)) {
						console.log(symbol);
					  } */
				}
			}
		});

/* 		Stalker.follow(TID, {
			events: {call: true},
					
			onReceive: function (events) {
				console.log("onReceive called.");
			},
			onCallSummary: function (summary) {
				console.log("onCallSummary called.");
			}
		}) */
    },
    onLeave: function (retval) {
		console.log(retval);

		Stalker.unfollow(TID);
		Stalker.garbageCollect();
	}
});

//connect
var ptrconnect = Module.findExportByName("Ws2_32.dll", "connect");
Interceptor.attach(ptrconnect, {
    onEnter: function (args) {
        console.log(" connect() Called");
    },
    onLeave: function (retval) {
	}
});

//WinExec
var ptrWinExec = Module.findExportByName("Kernel32.dll", "WinExec");
Interceptor.attach(ptrWinExec, {
    onEnter: function (args) {
        console.log(" WinExec() Called");
		console.log("    | -- CMD Line " + args[0].readAnsiString());
    },
    onLeave: function (retval) {
	}
});

//RtlCopyMemory
var ptrRtlCopyMemory = Module.findExportByName("Kernel32.dll", "RtlCopyMemory");
Interceptor.attach(ptrRtlCopyMemory, {
    onEnter: function (args) {
        console.log(" RtlCopyMemory() Called");
    },
    onLeave: function (retval) {
	}
});