# import subprocess

# def run_die(file_path):
#     # Path to the diec executable
#     diec_path = "path/to/diec"  # Adjust this to the path where diec is located

#     # Run the diec command with the file path
#     result = subprocess.run([diec_path, file_path], capture_output=True, text=True)

#     # Print the output from DIE
#     if result.returncode == 0:
#         print("DIE Output:")
#         print(result.stdout)
#     else:
#         print("Error running DIE:")
#         print(result.stderr)

# # Example usage
# file_to_analyze = "path/to/your/file"
# run_die(file_to_analyze)


# import shutil

# def is_die_installed():
#     die_path = shutil.which("diec")
#     if die_path:
#         print(f"DIE CLI is installed at: {die_path}")
#         return True
#     else:
#         print("DIE CLI is not installed or not in the system's PATH.")
#         return False

# if __name__ == "__main__":
#     is_die_installed()


import subprocess
import os


def run_die(diec_path, file_path):
    # Run the diec command with the file path
    result = subprocess.run([diec_path, file_path], capture_output=True, text=True)

    # Print the output from DIE
    if result.returncode == 0:
        print("DIE Output:")
        print(result.stdout)
    else:
        print("Error running DIE:")
        print(result.stderr)


# Example usage
diec_path = os.path.abspath("diec.sh")  # Adjust this to the relative path from the script location
file_to_analyze = os.path.abspath("notepad++.exe")

run_die(diec_path, file_to_analyze)
