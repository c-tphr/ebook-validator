"""Trusted pinned dependency installation for supported Colab runtime images."""

import hashlib
import os
from pathlib import Path
import platform
import pwd
import shutil
import subprocess
import sys
import tempfile
from urllib.request import urlopen
from zipfile import ZipFile

SNAPSHOT = "20261110T000000Z"
PACKAGES = ("bubblewrap", "strace", "clamav", "clamav-freshclam", "default-jre-headless",
            "python3-lxml", "python3-tinycss2", "python3-pyqt5", "libpango-1.0-0",
            "libpangoft2-1.0-0", "libharfbuzz-subset0",
            "fonts-dejavu-core", "libseccomp2")
EPUBCHECK_URL = "https://github.com/w3c/epubcheck/releases/download/v5.4.0/epubcheck-5.4.0.zip"
EPUBCHECK_FILES = {
    'epubcheck.jar': '2146665a124998dc6c908010ffe0d09dc4f4c8014f2c8fd6a1aa11f64c40ac93',
    'lib/Saxon-HE-11.4.jar': '42e35494dc2e6b5e97256ae7cdf2b7ce30439c352566f35de02bed3a06a2b169',
    'lib/accessors-smart-2.4.9.jar': 'accdd5c7ac4c49b155890aaea1ffca2a9ccd5826b562dd95a99fc1887003e031',
    'lib/asm-9.3.jar': '1263369b59e29c943918de11d6d6152e2ec6085ce63e5710516f8c67d368e4bc',
    'lib/common-image-3.9.4.jar': 'a5f41991d2492f28ce4f04b82abfffb89f5ffa9dfc87f4e58f10d526e5ba4a83',
    'lib/common-io-3.9.4.jar': 'cc7c27947bf21a75fbc3d613e79bdd8619908e67b88cc7d73091a55876e4fd38',
    'lib/common-lang-3.9.4.jar': 'a521b797d58f65b80fa8ca365d95911622408cab220fd5d852169805f640acbd',
    'lib/commons-codec-1.19.0.jar': '5c3881e4f556855e9c532927ee0c9dfde94cc66760d5805c031a59887070af5f',
    'lib/commons-compress-1.28.0.jar': 'e1522945218456f3649a39bc4afd70ce4bd466221519dba7d378f2141a4642ca',
    'lib/commons-io-2.20.0.jar': 'df90bba0fe3cb586b7f164e78fe8f8f4da3f2dd5c27fa645f888100ccc25dd72',
    'lib/commons-lang3-3.18.0.jar': '4eeeae8d20c078abb64b015ec158add383ac581571cddc45c68f0c9ae0230720',
    'lib/error_prone_annotations-2.36.0.jar': '77440e270b0bc9a249903c5a076c36a722c4886ca4f42675f2903a1c53ed61a5',
    'lib/failureaccess-1.0.3.jar': 'cbfc3906b19b8f55dd7cfd6dfe0aa4532e834250d7f080bd8d211a3e246b59cb',
    'lib/galimatias-0.1.3.jar': 'b37cbc4513584ed6aa1d8f7529ebe77abbe28c1f54ec63b0ff28a00a2d9d2a9a',
    'lib/guava-33.4.8-jre.jar': 'f3d7f57f67fd622f4d468dfdd692b3a5e3909246c28017ac3263405f0fe617ed',
    'lib/httpclient5-5.1.3.jar': '28c759254f4e35319e078bb6ffea75676608dc12cb243b24fb3c8732522977fe',
    'lib/httpcore5-5.1.3.jar': 'f2bf2f2c7772169c9e30699719667ad30f9b46c4e9d7841907deb2d12d9923fe',
    'lib/httpcore5-h2-5.1.3.jar': 'd0e78ba15aa8ebe77982b660ac4b09a95d6e035dbdbea762577dc1c8e2935807',
    'lib/icu4j-77.1.jar': 'b3640b9f416a4411fd33c59abbeea8fd57d024c23e1819bf9673220a97499fe3',
    'lib/imageio-core-3.9.4.jar': '244843a7bc8ecf6efb20aa5f817e977addafb3f6b0ce70393b3e6d1109591fae',
    'lib/imageio-jpeg-3.9.4.jar': 'cdc95ecde53b012774790ead020879af6c76928c8d8e0be4b964528937ec1b7d',
    'lib/imageio-metadata-3.9.4.jar': '580a334f8e20c99ff9127fa9b0022b0f02a981b46e6b38e0df393052329a6324',
    'lib/isorelax-20030108.jar': '3427152431cf7f967f92e69e5cac16147c5d8fb4b4e5a8a72f5291788efcff8c',
    'lib/j2objc-annotations-3.0.0.jar': '88241573467ddca44ffd4d74aa04c2bbfd11bf7c17e0c342c94c9de7a70a7c64',
    'lib/jackson-annotations-2.18.9.jar': '798c85b86e7420d0b4eb91e7b3e37d4bee673c61de37a616ba51a7539631e6b7',
    'lib/jackson-core-2.18.8.jar': 'ab865e39f01403598748b090a3bf528616e701913a71afc37a227daa0fabb4ae',
    'lib/jackson-databind-2.18.9.jar': '71595a3f7ff58344ec0496a9f9ec9f623ef7b85b45402d88f1ca261f1bc4b42c',
    'lib/jing-20181222.jar': 'e5e13fa92d9461f37b7c3d760780ea07cca5b7947440f99ebb7608b5b168aaa3',
    'lib/json-path-2.8.0.jar': '9601707e95cd79fb98570a01ea8cfb857b5cde948744d6e0edf733c11002c95b',
    'lib/json-path-assert-2.8.0.jar': '5de6305e6e1df4f4c1ad603f1d7ac2394b474c767b8165701a492643ac34a56a',
    'lib/json-smart-2.4.10.jar': '70cab5e9488630dc631b1fc6e7fa550d95cddd19ba14db39ceca7cabfbd4e5ae',
    'lib/jspecify-1.0.0.jar': '1fad6e6be7557781e4d33729d49ae1cdc8fdda6fe477bb0cc68ce351eafdfbab',
    'lib/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar': 'b372a037d4230aa57fbeffdef30fd6123f9c0c2db85d0aced00c91b974f33f99',
    'lib/sac-1.3.jar': '003785669f921aafe4f137468dd20a01a36111e94fd7449f26c16e7924d82d23',
    'lib/slf4j-api-1.7.36.jar': 'd3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0',
    'lib/slf4j-nop-1.7.36.jar': 'c214958b07816cb4412b30c7bdbd4308ffdc6ba2a83767b8f3a9229cbd9274d6',
    'lib/xercesImpl-2.12.2.jar': '6fc991829af1708d15aea50c66f0beadcd2cfeb6968e0b2f55c1b0909883fe16',
    'lib/xml-apis-1.4.01.jar': 'a840968176645684bb01aed376e067ab39614885f9eee44abe35a5f20ebe7fad',
    'lib/xmlresolver-4.4.3-data.jar': 'a57db23d75c3580cb15eb6e1a854683f4579cfd265f5cf1011a6983d9aed0f1f',
    'lib/xmlresolver-4.4.3.jar': '9d642c96c3f6811e20a9f6cfee3ca15ec84ecb939f6be639fee065670773a7d1',
}


def run_tool(command, timeout=180):
    result = subprocess.run(command, capture_output=True, env={
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
        "DEBIAN_FRONTEND": "noninteractive",
    }, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"{Path(command[0]).name} failed ({result.returncode}).")
    return result.stdout.decode("utf-8", errors="replace")


def install_packages():
    release = platform.freedesktop_os_release()
    suite = release.get("VERSION_CODENAME")
    if os.geteuid() != 0 or release.get("ID") != "ubuntu" or suite != "noble":
        raise RuntimeError("Automatic installation requires a root Ubuntu 24.04 runtime.")
    if platform.machine() != "x86_64":
        raise RuntimeError("This setup manifest targets Ubuntu amd64.")
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory, "v5.list")
        source.write_text(
            "".join(f"deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
                        f"https://snapshot.ubuntu.com/ubuntu/{SNAPSHOT}/ {pocket} main universe\n"
                        for pocket in (suite, suite + "-updates", suite + "-security"))
        )
        options = ["-o", f"Dir::Etc::SourceList={source}", "-o", "Dir::Etc::SourceParts=-"]
        run_tool(["/usr/bin/apt-get", *options, "update"])
        pins = {}
        for name in PACKAGES:
            lines = run_tool(["/usr/bin/apt-cache", *options, "madison", name]).splitlines()
            versions = [row.split("|")[1].strip() for row in lines if "snapshot.ubuntu.com" in row]
            if not versions:
                raise RuntimeError(f"Pinned snapshot package unavailable: {name}.")
            pins[name] = versions[0]
        run_tool(["/usr/bin/apt-get", *options, "-y", "--no-install-recommends", "install",
                  *(name + "=" + version for name, version in pins.items())], timeout=600)
        for name, required in pins.items():
            if run_tool(["/usr/bin/dpkg-query", "-W", "-f=${Version}", name]) != required:
                raise RuntimeError(f"Installed package identity changed: {name}.")
    return pins


def install_epubcheck(destination):
    destination.mkdir(mode=0o755, exist_ok=False)
    destination.chmod(0o755)
    with tempfile.TemporaryFile() as archive, urlopen(EPUBCHECK_URL, timeout=45) as response:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > 80 * 1024 * 1024:
                raise RuntimeError("EPUBCheck release exceeds the download bound.")
            archive.write(chunk)
        archive.seek(0)
        with ZipFile(archive) as release:
            for name, expected in EPUBCHECK_FILES.items():
                info = release.getinfo("epubcheck-5.4.0/" + name)
                if not 0 < info.file_size <= 20 * 1024 * 1024:
                    raise RuntimeError("Unexpected EPUBCheck component size.")
                data = release.read(info)
                if hashlib.sha256(data).hexdigest() != expected:
                    raise RuntimeError("EPUBCheck component failed pinned hash verification.")
                target = destination / name
                target.parent.mkdir(mode=0o755, exist_ok=True)
                target.parent.chmod(0o755)
                target.write_bytes(data)
                target.chmod(0o444)
    return destination / "epubcheck.jar"


def refresh(database, configuration=None):
    database.mkdir(mode=0o755, exist_ok=True)
    database.chmod(0o755)
    steward = pwd.getpwnam("clamav") if os.geteuid() == 0 else pwd.getpwuid(os.geteuid())
    if os.geteuid() == 0:
        os.chown(database, steward.pw_uid, steward.pw_gid)
    if configuration:
        return run_tool(["/usr/bin/freshclam", f"--datadir={database}",
                         f"--config-file={configuration}"], timeout=600)
    # Avoid inherited log files, locks, notification hooks and updater
    # settings from the host's system service.
    config = database.parent / "freshclam-v5.conf"
    config.write_text(f"DatabaseOwner {steward.pw_name}\n"
                      "DatabaseMirror database.clamav.net\n"
                      "ConnectTimeout 10\nReceiveTimeout 60\nMaxAttempts 1\n")
    config.chmod(0o444)
    return run_tool(["/usr/bin/freshclam", f"--datadir={database}", f"--config-file={config}"],
                    timeout=600)


def setup_versions():
    tools = {}
    for tool, flag in (("bwrap", "--version"), ("strace", "--version"), ("java", "-version"),
                       ("clamscan", "--version"), ("freshclam", "--version"),
                       ("python3", "--version")):
        executable = Path("/usr/bin", tool)
        try:
            resolved = executable.resolve(strict=True)
            result = subprocess.run([str(executable), flag], capture_output=True, timeout=15, env={
                "PATH": "/usr/bin:/bin", "LANG": "C",
            })
            with resolved.open("rb") as binary:
                sha = hashlib.file_digest(binary, "sha256").hexdigest()
            first = (result.stdout or result.stderr).decode(errors="replace").splitlines()
            tools[tool] = {"version": first[0][:200] if first else None,
                           "sha256": sha, "path": str(resolved), "ok": result.returncode == 0}
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            tools[tool] = {"ok": False}
    return {"platform": platform.platform(), "libc": platform.libc_ver(), "tools": tools,
            "tmp_free_bytes": shutil.disk_usage("/tmp").free}


WEASY_LOCK = """\
brotli==1.2.1 --hash=sha256:4b9dd0173ca5e01d1eb307d3c184fe8c09bdc168ede560889b1018d216d38c61
cffi==2.1.1 --hash=sha256:c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf
cssselect2==0.10.1 --hash=sha256:25cc4494d55985d6a6da359be48da6ce98c28dcbafa2314c383ace3fc32ec868
fonttools==4.68.0 --hash=sha256:3edce69ecdefa73ab1041901ca22eefed6ebb93a77bc77e889d940479f25bf7d
pillow==13.0.0 --hash=sha256:42d63be3af4f9b951b199b0a9d23365d37ab14687e6d77b74940432c8515c4ca
pycparser==3.12 --hash=sha256:a076f3f489b39b43ed13563a1dafe42447445bec2e294154ec5c57fcdda4c85e
pydyf==0.13.0 --hash=sha256:85b28a3af8c35e6fe1415f2b3f1d6851cb3b52f53592c2cda4db9a00a8979677
pyphen==0.18.1 --hash=sha256:0aa9051e15928cecadd4c632cea0258ba57215b2a197a39baa46abcdb0f47e84
tinycss2==1.5.1 --hash=sha256:3415ba0f5839c062696996998176c4a3751d18b7edaaeeb658c9ce21ec150661
tinyhtml5==2.1.0 --hash=sha256:6e11cfff38515834268daf89d5f85bbde0b6dd02e8d9e212d1385c2289b89f0a
weasyprint==70.0 --hash=sha256:5043e55e38d2a2af2b2b871e869697b1f65dad5f8b4a3677961d04ceacf9c5fe
webencodings==0.6.1 --hash=sha256:7fab6269c8bf237c657876b52058ccb182e861518d1c695c1a9aaa8c1c105d5b
zopfli==0.4.3 --hash=sha256:769875152d0625c46707bcca57d4b2233fe653482067acd55fbf6ec525cb9bdc
"""

def install_weasyprint(destination):
    if run_tool(["/usr/bin/python3", "-c", "import sys; print(sys.version[:4])"]).strip() != "3.12":
        raise RuntimeError("The compatible WeasyPrint lock requires system Python 3.12.")
    with tempfile.TemporaryDirectory() as folder:
        lock = Path(folder) / "requirements.txt"
        lock.write_text(WEASY_LOCK)
        run_tool([sys.executable, "-m", "pip", "--isolated", "install", "--require-hashes", "--no-deps",
                  "--index-url", "https://pypi.org/simple", "--only-binary", ":all:", "--python-version", "3.12",
                  "--platform", "manylinux_2_28_x86_64", "--platform", "manylinux2014_x86_64",
                  "--abi", "cp312", "--target", str(destination), "-r", str(lock)], timeout=300)
    for path in (destination, *destination.rglob("*")):
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            path.chmod(path.stat().st_mode | 0o444)
    return destination
