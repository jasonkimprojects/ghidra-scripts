"""
Uses Ghidra's Python API to find libc functions called in a binary
that are dangerous, according to Intel's safestringlib, viewable at
https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions.

Run me in Ghidra's Jython interpreter like this:
execfile("<PATH>/find_dangerous_functions.py")
Since there is no Jython 3 (yet), this script is in Python 2.

Ensure that you have imported the binary in ELF format this time!
The symbol table is crucial.
"""

danger = ["alloca", "scanf", "wscanf", "sscanf", "swscanf", "vscanf",
            "vsscanf", "strlen", "wcslen", "strtok", "strtok_r", "wcstok",
            "strcat", "strncat", "wcscat", "wcsncat", "strcpy", "strncpy",
            "wcscpy", "wcsncpy", "memcpy", "wmemcpy", "stpcpy", "stpncpy",
            "wcpcpy", "wcpncpy", "memmove", "wmemmove", "memcmp", "wmemcmp",
            "memset", "wmemset", "gets", "sprintf", "vsprintf", "swprintf",
            "vswprintf", "snprintf", "vsnprintf", "realpath", "getwd",
            "wctomb", "wcrtomb", "wcstombs", "wcsrtombs", "wcsnrtombs"]

prgm = ghidra.program.flatapi.FlatProgramAPI(currentProgram)
listing = currentProgram.getListing()
fn = prgm.getFirstFunction()

while fn is not None:
    if str(fn.getName()) in danger:
        print "Dangerous function found: {}".format(fn.getName())
        print "Entry point: {}".format(fn.getEntryPoint())
        dummy = ghidra.util.task.TaskMonitor.DUMMY
        called_by = fn.getCallingFunctions(dummy)
        for caller in called_by:
            print "{} is called by: {} at {}\n".format(
                    fn.getName(), caller.getName(), caller.getEntryPoint())

    fn = prgm.getFunctionAfter(fn)
