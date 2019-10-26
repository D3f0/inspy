import itertools
import os
import re
import shlex
import signal
import stat
import sys
from pathlib import Path
from shutil import which
from typing import Optional

import appdirs
import click
import sh
from loguru import logger

CONFIG_DIR = Path(appdirs.user_config_dir("inspy"))


def docker(cmd, **args):
    """
    Runs a docker command with sh
    """
    return sh.docker(shlex.split(cmd), **args)


def xquartz_running() -> bool:
    for line in sh.ps("-x"):
        if "X11" in line:
            return True
    return False


def get_ips():
    output = sh.ifconfig()
    for match in re.findall("inet (addr:)?(([0-9]*\.){3}[0-9]*)", str(output)):
        _, ip, *_ = match
        if ip.startswith("127"):
            continue
        yield ip


def get_certs(subj: Optional[str] = None, filename: str = "cert"):
    """Creates a certificate for mitmproxy using openssl. If exists
    returns the previously created one

    Keyword Arguments:
        subj {[type]} -- [description] (default: {None})
        dest {[type]} -- [description] (default: {None})
        filename {str} -- [description] (default: {'cert'})

    Returns:
        [type] -- [description]
    """
    if subj is None:
        subj = (
            "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"
        )
    base = CONFIG_DIR
    key = base / f"{filename}.key"
    if not key.exists():
        logger.info(f"Generating {key}")
        sh.openssl(shlex.split(f"genrsa -out {key.name} 2048"), _cwd=CONFIG_DIR)

    crt = base / f"{filename}.crt"
    if not crt.exists():
        logger.info(f"Generating {crt}")
        sh.openssl(
            shlex.split(
                f"req -new -x509 -key {key.name} -out {crt.name} -subj '{subj}'"
            ),
            _cwd=str(base),
        )

    pem = base / f"{filename}.pem"
    if not pem.exists():
        logger.info(f"Generating {pem}")
        with pem.open("w") as fp:
            for pth in (key, crt):
                fp.write(pth.read_text())
    return pem


COMMAND = """\
#!/bin/bash
apt-get update -yq
apt-get install -yq ca-certificates sudo
mkdir -p /usr/share/ca-certificates/extra
cp /config/cert.crt /usr/share/ca-certificates/extra/
dpkg-reconfigure ca-certificates
update-ca-certificates
sudo -u chromium chromium --no-sandbox --proxy-server=http://host.docker.internal:8080
"""


def generate_command():
    bash_script = CONFIG_DIR / "command.sh"
    if not bash_script.exists() or bash_script.read_text() != COMMAND:
        with bash_script.open("w") as fp:
            fp.write(COMMAND)
    os.chmod(bash_script, 0o755)


def free_port(port=int) -> None:
    for line in sh.lsof("-i", f":{port}").splitlines()[1:]:
        name, pid, *_ = line.split()
        logger.info(f"Killing {name} (PID {pid}) using port {port}")
        os.kill(int(pid), signal.SIGKILL)


@click.command(
    epilog="Creates SSL certificates in your host machine and starts a browser"
)
@click.option("-n", "--name", default="remmina", help="Container name")
@click.option(
    "-s", "--image", default="jess/chromium", show_default=True, help="Container image"
)
@click.option(
    "-i",
    "--local-ip-num",
    "local_ip_num",
    type=int,
    help="Which of the local ips",
    default=0,
)
@click.option("-I", "--ip", "explicit_ip", default=None, help="Specify a local IP")
@click.option(
    "-c", "--clean", "clean", default=False, is_flag=True, help="Clean config directory"
)
@click.option('-p', '--port', default=8080, help="Port for mtimproxy")
def main(image, name, local_ip_num, explicit_ip, clean, port):
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(parents=True)

    if not which('mitmproxy'):
        logger.critical("mitmproxy not in path. Aborting...")
        return -1

    contents = CONFIG_DIR.glob("**/*")
    if clean:
        logger.info(f"Cleaning {CONFIG_DIR}")
        for f in contents:
            f.unlink()
        return

    logger.info(f"Config dir: {CONFIG_DIR}:")
    for f in CONFIG_DIR.glob("**/*"):
        logger.info(f"\t{f.name}")
    pem: Path = get_certs()
    try:
        container_id = sh.docker("ps", "--quiet", "--all", f"--filter=name={name}")
    except sh.CommandError:
        pass
    except sh.ErrorReturnCode as error:
        click.echo(
            "Docker returned an error while running. Is the service running?"
            f" {error}"
        )
        sys.exit(1)
    container_id = container_id.strip()
    if container_id:
        logger.info(f"Stopping previous container {container_id}")
        sh.docker("rm", "-f", container_id)

    if not explicit_ip:
        local_ips = list(get_ips())
        if not 0 <= local_ip_num <= len(local_ips):
            click.echo(
                message="-i/--local-ip-num must be between 0 and {len(local_ips)}"
            )
            return 1
        ip = local_ips[local_ip_num]
    else:
        ip = explicit_ip

    click.echo("Using IP: {}".format(ip))
    if not xquartz_running():
        sh.open("-a", "XQuartz")
    print(sh.Command("/opt/X11/bin/xhost")("+", ip))

    generate_command()

    container_id = sh.docker(
        "run", "--rm", "-u", "root",   # Transient, user
        "-v", f"{CONFIG_DIR.absolute()}:/config",  # Certs, and command file volume
        "--entrypoint", "bash", # Change chromium to bash
        "-e", "QT_X11_NO_MITSHM=1", # Some options
        "-e", f"DISPLAY={ip}:0",   # Display
        "-d",  # Launch in the bg
        image, "/config/command.sh",  # Last line image and command
    ).strip()
    sh.mitmproxy("--cert", CONFIG_DIR / "cert.pem", _fg=True)
    logger.info("Killing browser container")
    sh.docker('kill', container_id)

if __name__ == "__main__":
    main()
