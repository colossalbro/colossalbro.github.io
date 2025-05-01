// Flutter Detective - Find hidden Flutter libraries
Java.perform(function() {
    console.log("[*] Flutter Detective active");
    
    // Hook System.load which is used for loading libraries with absolute paths
    var System = Java.use("java.lang.System");
    System.load.implementation = function(absolutePath) {
        console.log("[+] System.load called with: " + absolutePath);
        try {
            this.load(absolutePath);
            console.log("[+] Successfully loaded: " + absolutePath);
            
            // Check if this might be a Flutter library
            checkForFlutterSignatures(absolutePath);
        } catch(e) {
            console.log("[-] Failed to load: " + absolutePath + " - " + e);
            throw e;
        }
    };
    
    // Hook System.loadLibrary
    System.loadLibrary.overload("java.lang.String").implementation = function(libraryName) {
        console.log("[+] System.loadLibrary called with: " + libraryName);
        try {
            this.loadLibrary(libraryName);
            console.log("[+] Successfully loaded library: " + libraryName);
            
            // After loading, try to find the actual path
            var loaded = Process.findModuleByName(libraryName + ".so") || 
                         Process.findModuleByName("lib" + libraryName + ".so");
                         
            if (loaded) {
                console.log("[+] Found at: " + loaded.path);
                // Check if this might be a Flutter library
                checkForFlutterSignatures(loaded.path);
            }
        } catch(e) {
            console.log("[-] Failed to load library: " + libraryName + " - " + e);
            throw e;
        }
    };
    
    // Hook dlopen to catch native library loading
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            this.path = args[0].readUtf8String();
            console.log("[+] dlopen called: " + this.path);
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                console.log("[+] dlopen succeeded: " + this.path);
                // Check if this might be a Flutter library
                checkForFlutterSignatures(this.path);
            } else {
                console.log("[-] dlopen failed: " + this.path);
            }
        }
    });
    
    // Monitor file access to detect library extraction
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload("java.lang.String").implementation = function(path) {
        if (path.endsWith(".so") || path.includes("/lib/")) {
            console.log("[+] Accessing potential library file: " + path);
        }
        return this.$init(path);
    };
    
    // Function to check if a library might be Flutter-related
    function checkForFlutterSignatures(path) {
        try {
            if (!path) return;
            
            // Try to load the module if not already loaded
            var module = Process.findModuleByName(path.split("/").pop()) || 
                        Process.getModuleByPath(path);
                        
            if (!module) {
                console.log("[-] Couldn't access module at: " + path);
                return;
            }
            
            console.log("[*] Scanning module for Flutter signatures: " + module.name);
            
            // Look for common Flutter strings
            var flutterStrings = ["Flutter", "Dart", "Observatory", "dart:core"];
            var flutterFound = false;
            
            for (var i = 0; i < flutterStrings.length; i++) {
                var pattern = flutterStrings[i];
                Memory.scan(module.base, module.size, pattern, {
                    onMatch: function(address, size) {
                        if (!flutterFound) {
                            console.log("[!] Found Flutter signature in: " + module.name);
                            flutterFound = true;
                        }
                        console.log("    - Match at: " + address + " - " + pattern);
                    }
                });
            }
            
            // Also look for common Flutter symbols
            var exports = Module.enumerateExportsSync(module.name);
            exports.forEach(function(exp) {
                if (exp.name.includes("Flutter") || exp.name.includes("Dart")) {
                    if (!flutterFound) {
                        console.log("[!] Found Flutter export in: " + module.name);
                        flutterFound = true;
                    }
                    console.log("    - Export: " + exp.name);
                }
            });
            
        } catch (e) {
            console.log("[-] Error scanning module: " + e);
        }
    }
    
    // List all currently loaded modules
    console.log("[*] Currently loaded modules:");
    Process.enumerateModules().forEach(function(module) {
        console.log("    " + module.name + " - " + module.path);
        // Also check existing modules for Flutter signatures
        checkForFlutterSignatures(module.path);
    });
    
    console.log("[*] Flutter Detective is now monitoring for library loads...");
});