"""
Given a minimum length (in bytes) as a command-line argument,
uses Ghidra's Python API to print and bookmark the start and end
addresses of code cave(s) larger than or equal to minimum length.
This script detects 0x00, 0xCC and 0xFF as filler bytes.

Run me in Ghidra's Jython interpreter like this:
execfile("<PATH>/find_code_caves.py")
Since there is no Jython 3 (yet), this script is in Python 2.

Ensure that you have imported the binary as a raw binary, NOT in ELF format.

Jason Kim
Sunday, August 2, 2020
"""

# TUNEABLE PARAMETER: the script will alert on code caves that are
# at least min_len bytes.
min_len = 50
start_addr = currentProgram.getMinAddress()
end_addr = currentProgram.getMaxAddress()
prgm = ghidra.program.flatapi.FlatProgramAPI(currentProgram)

streak = 0
cave_start = ''
print "Starting search"

while start_addr <= end_addr:
    data = prgm.getUndefinedDataAt(start_addr)
    if data is None:
        if streak > min_len:
            print "Code cave of length {} found from {} to {}".format(
            streak - 1, cave_start, start_addr.previous().toString())
        cave_start = ''
        streak = 0
    else:
        data = data.getDefaultValueRepresentation()
        if data in [u'00h', u'CCh', u'FFh']:
            streak += 1
            if not cave_start:
                cave_start = start_addr.toString()
        else:
            if streak > min_len:
                print "Code cave of length {} found from {} to {}".format(
                streak - 1, cave_start, start_addr.previous().toString())
            cave_start = ''
            streak = 0
    start_addr = start_addr.next()

print "End of search"
