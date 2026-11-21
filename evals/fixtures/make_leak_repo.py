"""Build the 'leak' eval fixture: a git repo whose history holds a fake AWS key that a later commit removed.
Usage: python make_leak_repo.py OUT_DIR. The key is assembled at run time so this file holds no key-shaped string."""
import os, subprocess, sys

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
def git(*a):
    subprocess.run(["git", "-C", out, *a], check=True, capture_output=True)
git("init", "-q", "-b", "main")
git("config", "user.email", "dev@example.invalid"); git("config", "user.name", "Dev")
key = "AKIA" + "Q7XK2M9PLW4RT6ZB"
secret = "wJalr" + "XUtnFEMI" + "K7MDENGbPxRfiCYzz" + "EXAMPLEKEY9"
with open(os.path.join(out, "config.py"), "w") as f:
    f.write(f'AWS_ACCESS_KEY_ID = "{key}"\nAWS_SECRET_ACCESS_KEY = "{secret}"\nBUCKET = "photos-backup"\n')
with open(os.path.join(out, "app.py"), "w") as f:
    f.write("from config import BUCKET\nprint(BUCKET)\n")
git("add", "."); git("commit", "-q", "-m", "Add S3 upload")
with open(os.path.join(out, "config.py"), "w") as f:
    f.write('import os\nAWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\nAWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]\nBUCKET = "photos-backup"\n')
git("commit", "-q", "-am", "Read keys from env")
print(out)
