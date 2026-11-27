############################################################################################################################
# XA Spy Build v1.02
# Build the native Windows C++ application with one command.
# Configures CMake, compiles Release x64, and verifies the executable and local IOC files.
# Python is used only for this build helper; XASpy.exe does not use Python.
# Core Features:
# • Finds installed Visual Studio C++ tools and CMake; never downloads dependencies.
# • Works from any current directory and preserves the existing build cache.
# • Streams compiler output to the console and a timestamped local log.
# • Uses XA blue stages, green success, orange warnings and red failures.
# • Keeps the console open on success or failure unless --no-pause is supplied.
# Important Note: Builds only. Does not launch XA Spy, scan data, or publish anything.
# Created by: XA Spy maintainers
# Last Updated: 2026-10-27 23:19:18
# Release Notes: v1.02 - Isolated candidates, synthetic tests, incremental backups and source-bound receipts.
#                v1.01 - XA console colors with plain logs and NO_COLOR support.
#                v1.00 - Initial native Release x64 build helper.
############################################################################################################################

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime
import traceback

from build_support.console_status import print_status as print, strip_ansi
from build_support.native_workflow import capture, complete, write_state


def report(message, log=None):
    print(message, flush=True)
    if log is not None:
        log.write(strip_ansi(message) + "\n")
        log.flush()


class BuildError(Exception):
    pass


def local_path(path):
    """Refuse redirected build/output paths without deleting or cleaning anything."""
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BuildError("Symlink/reparse path refused: " + str(part))
    return path


def query(command):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=30, check=False)
    if result.returncode:
        raise BuildError("Tool discovery failed: " + subprocess.list2cmdline(command))
    return result.stdout


def cache_values(build):
    cache = local_path(build / "CMakeCache.txt")
    values = {}
    if cache.exists():
        for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith(("#", "//")):
                key, value = line.split("=", 1)
                values[key.split(":", 1)[0]] = value
    return values


def normalized(path):
    return os.path.normcase(os.path.abspath(path))


def find_tools(build):
    installer = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    vswhere = installer / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        raise BuildError("Visual Studio Installer was not found. Install Visual Studio 2022 or newer "
                         "with Desktop development with C++, MSVC x64 tools and a Windows SDK.")
    instances = json.loads(query([str(vswhere), "-products", "*", "-version", "[17.0,19.0)",
                                  "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                                  "-format", "json", "-utf8"]))
    if not instances:
        raise BuildError("Visual Studio C++ x64 tools were not found. In Visual Studio Installer, "
                         "add Desktop development with C++, MSVC x64 tools and a Windows SDK.")
    instances.sort(key=lambda item: tuple(int(n) for n in item["installationVersion"].split(".")), reverse=True)
    selected = instances[0]
    cached_instance = cache_values(build).get("CMAKE_GENERATOR_INSTANCE", "")
    if cached_instance:
        selected = next((item for item in instances if normalized(item["installationPath"]) == normalized(cached_instance)), None)
        if selected is None:
            raise BuildError("The Visual Studio installation recorded in the selected build directory is unavailable. "
                             "Restore that installation or preserve/rename the build folder; it was not deleted.")
    major = int(selected["installationVersion"].split(".")[0])
    generator = {17: "Visual Studio 17 2022", 18: "Visual Studio 18 2026"}[major]
    minimum = (3, 24, 0) if major == 17 else (4, 2, 0)
    vs_path = Path(selected["installationPath"])
    candidates = [shutil.which("cmake.exe"),
                  str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CMake/bin/cmake.exe"),
                  str(vs_path / "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe")]
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file():
            continue
        try:
            match = re.search(r"cmake version (\d+)\.(\d+)\.(\d+)", query([candidate, "--version"]))
            if match and tuple(map(int, match.groups())) >= minimum:
                return candidate, generator, str(vs_path)
        except (BuildError, OSError, subprocess.TimeoutExpired):
            continue
    raise BuildError("CMake " + ".".join(map(str, minimum)) + "+ is required for " + generator +
                     ". Install CMake or Visual Studio's C++ CMake tools; nothing was downloaded.")


def check_cache(build, root, generator, instance):
    cache = local_path(build / "CMakeCache.txt")
    if not cache.exists():
        return
    values = cache_values(build)
    expected = {"CMAKE_GENERATOR": generator, "CMAKE_GENERATOR_PLATFORM": "x64"}
    for key, value in expected.items():
        if values.get(key) != value:
            raise BuildError("Existing selected build cache uses a different generator/architecture. "
                             "Preserve or rename that folder before starting a new build; it was not deleted.")
    for key, expected_path in (("CMAKE_HOME_DIRECTORY", root), ("CMAKE_GENERATOR_INSTANCE", Path(instance))):
        value = values.get(key, "")
        if not value or normalized(value) != normalized(expected_path):
            raise BuildError("Existing selected build cache belongs to another source/toolchain. "
                             "Preserve or rename that folder before retrying; it was not deleted.")


@contextlib.contextmanager
def build_lock(path):
    import msvcrt
    local_path(path)
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise BuildError("Another XA Spy build helper is already running.") from exc
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def run_stage(command, root, log):
    line = "\n> " + subprocess.list2cmdline(command)
    print(line, flush=True)
    log.write(strip_ansi(line) + "\n")
    log.flush()
    process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, errors="replace", bufsize=1,
                               creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        for line in process.stdout:
            print(line, end="", flush=True)
            log.write(strip_ansi(line))
            log.flush()
        code = process.wait()
    except BaseException:
        # Only the child process group belonging to this build is stopped.
        if process.poll() is None:
            import signal
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT)
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/taskkill.exe"
                subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
                process.wait(timeout=10)
        raise
    finally:
        process.stdout.close()
    if code:
        raise BuildError("Build stage failed with exit code " + str(code) + ". See the log above.")


def digest(path):
    value = hashlib.sha256()
    with local_path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.digest()


def ensure_executable_not_in_use(exe):
    """Refuse replacement of a mapped/running executable; never stop any app."""
    if not exe.exists():
        return
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.CreateFileW(str(exe), 0x40000000, 0, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise BuildError("The selected output executable is in use or not writable. Use --candidate "
                         "to preserve the running application, or close that copy yourself.")
    kernel.CloseHandle(handle)


def main():
    parser = argparse.ArgumentParser(description="Build XA Spy's native C++ application (Release x64).")
    parser.add_argument("--no-pause", action="store_true", help="Exit without waiting for Enter.")
    parser.add_argument("--candidate", action="store_true", help="Build out/candidate, preserving out/native and its running app.")
    parser.add_argument("--tests", action="store_true", help="Build and run synthetic native CTest fixtures; no live audit.")
    args = parser.parse_args()
    if os.name != "nt":
        raise BuildError("This build helper requires Windows.")
    if sys.version_info < (3, 11):
        raise BuildError("Python 3.11+ is required by the maintained incremental backup helpers.")
    root = local_path(Path(os.path.abspath(__file__)).parent)
    if not (root / "CMakeLists.txt").is_file():
        raise BuildError("CMakeLists.txt is missing beside this helper.")
    print("[STAGE] XA Spy - native C++ Release x64 build", flush=True)
    print("The application will not be launched. " +
          ("Synthetic native tests are enabled." if args.tests else "Tests are not requested."), flush=True)
    build = local_path(root / ("out/candidate" if args.candidate else "out/native"))
    local_path(root / "out").mkdir(exist_ok=True)
    logs = local_path(root / "out/build-logs")
    logs.mkdir(exist_ok=True)
    log_path = logs / ("build_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f") + ".log")
    print("Log: " + str(log_path), flush=True)
    with build_lock(root / "out/build.lock"), log_path.open("x", encoding="utf-8") as log:
        write_state(build, "in_progress", configuration={"candidate": args.candidate, "tests": args.tests})
        try:
            report("[STAGE 1/6] Check local inputs and installed build tools", log)
            for relative in ("Release/XASpy.exe", "Release/iocs", "CMakeFiles", "XASpy.dir"):
                local_path(build / relative)
            exe = local_path(build / "Release/XASpy.exe")
            ensure_executable_not_in_use(exe)
            source_iocs = local_path(root / "iocs")
            destination_iocs = local_path(build / "Release/iocs")
            required_iocs = ("adfection_iocs.txt", "curated_mercenary.txt", "LICENSE.md", "ESET-LICENSE.txt")
            for name in required_iocs:
                source = local_path(source_iocs / name)
                if not source.is_file() or not source.stat().st_size:
                    raise BuildError("Required source IOC file is missing or empty: " + name)
            for source in source_iocs.rglob("*"):
                local_path(source)
                local_path(destination_iocs / source.relative_to(source_iocs))
            cmake, generator, instance = find_tools(build)
            check_cache(build, root, generator, instance)
            ctest = str(Path(cmake).with_name("ctest.exe"))
            if args.tests and not Path(ctest).is_file():
                raise BuildError("ctest.exe is missing beside CMake; synthetic tests cannot run.")
            report("[OK] Local inputs and " + generator + " are ready", log)
            report("[STAGE 2/6] Capture verified incremental source recovery", log)
            snapshot = capture(root)
            report("[OK] Recovery manifest: " + str(snapshot), log)
            report("[STAGE 3/6] Configure native Release x64 build", log)
            run_stage([cmake, "-S", str(root), "-B", str(build), "-G", generator, "-A", "x64",
                       "-DCMAKE_GENERATOR_INSTANCE=" + instance,
                       "-DXA_SPY_BUILD_TESTS=" + ("ON" if args.tests else "OFF")], root, log)
            report("[OK] CMake configuration completed", log)
            report("[STAGE 4/6] Compile native targets", log)
            command = [cmake, "--build", str(build), "--config", "Release"]
            if not args.tests:
                command += ["--target", "XASpy"]
            run_stage(command + ["--parallel"], root, log)
            report("[OK] Native compilation completed", log)
            if args.tests:
                report("[STAGE 5/6] Run isolated synthetic native fixtures", log)
                run_stage([ctest, "--test-dir", str(build), "-C", "Release", "--output-on-failure", "--no-tests=error"], root, log)
                report("[OK] Synthetic native fixtures passed", log)
            else:
                report("[STAGE 5/6] Synthetic tests not requested (use --tests)", log)
            report("[STAGE 6/6] Verify executable, local data and source stability", log)
            if not exe.is_file() or exe.stat().st_size == 0:
                raise BuildError("Build returned success but XASpy.exe is missing or empty.")
            destination_iocs.mkdir(exist_ok=True)
            for source in source_iocs.iterdir():
                if source.is_file():
                    target = local_path(destination_iocs / source.name)
                    if not target.is_file() or digest(source) != digest(target):
                        shutil.copyfile(local_path(source), target)
                    if digest(source) != digest(target):
                        raise BuildError("Local IOC copy verification failed: " + source.name)
            for name in required_iocs:
                source, target = source_iocs / name, destination_iocs / name
                if not source.is_file() or not target.is_file() or digest(source) != digest(target):
                    raise BuildError("Required bundled IOC file is missing or mismatched: " + name)
            configuration = {"mode": "Release", "architecture": "x64", "generator": generator,
                             "instance": instance, "cmake": cmake, "synthetic_tests_passed": args.tests,
                             "candidate": args.candidate}
            outputs = [exe] + [path for path in destination_iocs.iterdir() if path.is_file()]
            complete(root, build, snapshot, configuration, outputs)
            report("\nBUILD SUCCESSFUL\nExecutable: " + str(exe) + "\nReceipt: " + str(build / "build-receipt.json"), log)
        except BaseException:
            log.write(strip_ansi(traceback.format_exc()))
            try:
                write_state(build, "failed", configuration={"candidate": args.candidate, "tests": args.tests})
            except Exception:
                log.write("Could not update failed receipt; success remains unconfirmed.\n")
            raise
    return 0


if __name__ == "__main__":
    exit_code = 1
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n[WARN] Build cancelled.", file=sys.stderr)
        exit_code = 130
    except Exception:
        details = traceback.format_exc()
        print("\nBUILD FAILED\n" + details, file=sys.stderr)
        try:
            folder = local_path(Path(os.path.abspath(__file__)).parent)
            crash = folder / ("crash_log_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f") + ".log")
            with crash.open("x", encoding="utf-8") as stream:
                stream.write(strip_ansi(details))
            print("Crash log: " + str(crash), file=sys.stderr)
        except (OSError, BuildError):
            pass
    finally:
        if "--no-pause" not in sys.argv and sys.stdin is not None and sys.stdin.isatty():
            try:
                input("\nPress Enter to close...")
            except (EOFError, KeyboardInterrupt):
                pass
    raise SystemExit(exit_code)
