import subprocess

# A script in another language that a workflow runs: the list form of a
# Compose build with a global option.
subprocess.run(["docker", "--context", "x", "compose", "build"], check=True)
