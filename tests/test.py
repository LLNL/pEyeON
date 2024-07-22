import os
import lief

binary_path = "Obsidian.1.1.9.exe"
binary = lief.PE.parse(binary_path)

# Save original value of modtime
orig_modtime = os.path.getmtime(binary_path)
print(orig_modtime)

# Add 1800 seconds to old modtime
new_modtime = orig_modtime + 1800
os.utime(binary_path, (new_modtime, new_modtime))
print(new_modtime)

if orig_modtime != new_modtime:
    print("modtimes have been modified")

# Verify modtime has been changed
modified_modtime = os.path.getmtime(binary_path)
print(modified_modtime)
