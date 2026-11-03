from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from support import CerberusCase, EXE, ROOT


def stage_source_project(destination: Path) -> None:
    destination.mkdir()
    shutil.copy2(ROOT / "setup.bat", destination / "setup.bat")
    for relative in ("src", "build/windows", "dependencies/opencl/include",
                     "dependencies/crypt_blowfish", "data/lists"):
        shutil.copytree(ROOT / relative, destination / relative)


class EntrypointTests(CerberusCase):
    def test_help_and_version_commands_exit_cleanly(self) -> None:
        help_run = self.invoke("--help")
        self.assertEqual(help_run.returncode, 0, help_run.stderr)
        self.assertIn("USAGE:", help_run.stdout)
        self.assertIn("COMMANDS:", help_run.stdout)

        version_run = self.invoke("--version")
        self.assertEqual(version_run.returncode, 0, version_run.stderr)
        self.assertIn("CERBERUS Forensic Suite v3.0", version_run.stdout)

    def test_interactive_menu_accepts_exit_without_running_a_search(self) -> None:
        completed = subprocess.run(
            [str(EXE)], cwd=self.cwd, input="0\n", capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("MODO INTUITIVO ZERO-CLICK", completed.stdout)
        self.assertIn("Encerrando sessao", completed.stdout)

    def test_interactive_menu_can_switch_to_cpu_engine(self) -> None:
        completed = subprocess.run(
            [str(EXE)], cwd=self.cwd, input="cpu\n0\n", capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Motor alterado para CPU", completed.stdout)
        self.assertIn("Encerrando sessao", completed.stdout)

    def test_setup_help_and_existing_runtime_diagnostic(self) -> None:
        if os.name != "nt":
            self.skipTest("setup.bat is Windows-only")
        setup = ROOT / "setup.bat"
        help_run = subprocess.run(
            ["cmd.exe", "/d", "/c", str(setup), "--help"], cwd=self.cwd,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=15, check=False,
        )
        self.assertEqual(help_run.returncode, 0, help_run.stdout + help_run.stderr)
        self.assertIn("Usage: setup.bat", help_run.stdout)

        check_run = subprocess.run(
            ["cmd.exe", "/d", "/c", str(setup)], cwd=self.cwd,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=30, check=False,
        )
        self.assertEqual(check_run.returncode, 0, check_run.stdout + check_run.stderr)
        self.assertIn("Checking the runtime", check_run.stdout)
        self.assertIn("Wordlist", check_run.stdout)
        self.assertIn("Saltlist", check_run.stdout)

    def test_native_cpp_unit_harness_compiles_and_passes(self) -> None:
        if os.name != "nt":
            self.skipTest("run_cpp_tests.bat is Windows-only")
        runner = ROOT / "tests" / "run_cpp_tests.bat"
        completed = subprocess.run(
            ["cmd.exe", "/d", "/c", str(runner)], cwd=ROOT,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=180, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertRegex(completed.stdout, r"\d+/\d+ native CERBERUS checks passed")

    def test_setup_build_modes_in_isolated_source_copies(self) -> None:
        if os.environ.get("CERBERUS_SKIP_SETUP_BUILD_TESTS") == "1":
            self.skipTest("setup build modes are exercised in the release workflow")
        if os.name != "nt":
            self.skipTest("setup.bat build modes are Windows-only")

        vs_path = os.environ.get("VS_PATH")
        vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
            "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
        if not vs_path and vswhere.is_file():
            located = subprocess.run(
                [str(vswhere), "-latest", "-products", "*", "-requires",
                 "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                 "-property", "installationPath"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if located.returncode == 0:
                vs_path = located.stdout.strip()
        if not vs_path or not (Path(vs_path) / "VC" / "Auxiliary" / "Build" /
                               "vcvarsall.bat").is_file():
            self.skipTest("Visual Studio C++ x64 build tools are not installed")

        cuda_path = os.environ.get("CUDA_PATH")
        if not cuda_path or not (Path(cuda_path) / "bin" / "nvcc.exe").is_file():
            cuda_path = None
        modes = ["--cpu-only", "--build"]
        if cuda_path:
            modes.append("--require-cuda")

        for mode in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                prefix="cerberus-setup-build-"
            ) as temp_dir:
                project = Path(temp_dir) / "project"
                stage_source_project(project)
                env = os.environ.copy()
                env["VS_PATH"] = vs_path
                env.pop("CUDA_ARCH", None)
                if cuda_path:
                    env["CUDA_PATH"] = cuda_path
                elif mode == "--cpu-only":
                    env.pop("CUDA_PATH", None)
                completed = subprocess.run(
                    ["cmd.exe", "/d", "/c", "setup.bat", mode], cwd=project,
                    env=env, capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=360, check=False,
                )
                self.assertEqual(
                    completed.returncode, 0,
                    f"setup.bat {mode} failed\n{completed.stdout}\n{completed.stderr}",
                )
                self.assertTrue((project / "cerberus.exe").is_file(), completed.stdout)
                self.assertIn("Build Complete", completed.stdout)
                if mode == "--require-cuda":
                    self.assertIn("CUDA backend is enabled", completed.stdout)

                version = subprocess.run(
                    [str(project / "cerberus.exe"), "--version"], cwd=project,
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=15, check=False,
                )
                self.assertEqual(version.returncode, 0, version.stdout + version.stderr)
                self.assertIn("CERBERUS Forensic Suite v3.0", version.stdout)

    def test_cuda_kernel_compile_failure_preserves_previous_executable(self) -> None:
        if os.environ.get("CERBERUS_SKIP_SETUP_BUILD_TESTS") == "1":
            self.skipTest("CUDA build failure injection is exercised in release CI")
        if os.name != "nt":
            self.skipTest("NVCC build failure injection is Windows-only")

        cuda_path = os.environ.get("CUDA_PATH")
        if not cuda_path or not (Path(cuda_path) / "bin" / "nvcc.exe").is_file():
            self.skipTest("CUDA Toolkit is not installed")
        vs_path = os.environ.get("VS_PATH")
        if not vs_path:
            vswhere = Path(os.environ.get("ProgramFiles(x86)",
                                          r"C:\Program Files (x86)")) / \
                "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
            located = subprocess.run(
                [str(vswhere), "-latest", "-products", "*", "-requires",
                 "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                 "-property", "installationPath"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if located.returncode == 0:
                vs_path = located.stdout.strip()
        if not vs_path:
            self.skipTest("Visual Studio C++ x64 build tools are not installed")

        with tempfile.TemporaryDirectory(prefix="cerberus-cuda-failure-") as temp_dir:
            project = Path(temp_dir) / "project"
            stage_source_project(project)
            existing_executable = b"previous known-good executable"
            (project / "cerberus.exe").write_bytes(existing_executable)
            kernel = project / "src" / "algorithms" / "gpu_kernels.cu"
            with kernel.open("a", encoding="utf-8", newline="") as output:
                output.write("\n__global__ void broken_test_kernel( { }\n")

            env = os.environ.copy()
            env["VS_PATH"] = vs_path
            env["CUDA_PATH"] = cuda_path
            env.pop("CUDA_ARCH", None)
            completed = subprocess.run(
                ["cmd.exe", "/d", "/c", "setup.bat", "--require-cuda"],
                cwd=project, env=env, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=180, check=False,
            )
            self.assertNotEqual(completed.returncode, 0,
                                completed.stdout + completed.stderr)
            self.assertIn("CUDA compilation failed", completed.stdout)
            self.assertEqual((project / "cerberus.exe").read_bytes(),
                             existing_executable)

    def test_visual_studio_project_and_release_package_manifest_are_consistent(self) -> None:
        namespace = {"msbuild": "http://schemas.microsoft.com/developer/msbuild/2003"}
        project_path = ROOT / "build" / "windows" / "cerberus.vcxproj"
        filters_path = ROOT / "build" / "windows" / "cerberus.vcxproj.filters"
        project = ET.parse(project_path).getroot()
        filters = ET.parse(filters_path).getroot()
        configurations = {
            item.attrib["Include"]
            for item in project.findall(
                ".//msbuild:ProjectConfiguration", namespace
            )
        }
        self.assertIn("Release|x64", configurations)
        self.assertIn("Debug|x64", configurations)

        compile_sources = {
            item.attrib["Include"].replace("\\", "/").lower()
            for item in project.findall(".//msbuild:ClCompile", namespace)
            if "Include" in item.attrib
        }
        self.assertIn("../../src/cerberus.cpp", compile_sources)
        self.assertIn("../../src/algorithms/opencl_kernels.cpp", compile_sources)
        self.assertIn("../../dependencies/crypt_blowfish/crypt_blowfish.c", compile_sources)
        cuda_builds = project.findall(".//msbuild:CustomBuild", namespace)
        self.assertTrue(
            any("gpu_kernels.cu" in item.attrib.get("Include", "").lower()
                for item in cuda_builds)
        )
        self.assertTrue(filters.findall(".//msbuild:CustomBuild", namespace))

        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        for artifact in (
            "cerberus.exe", "setup.bat", "README.md", "LICENSE",
            "data/lists/wordlist.txt", "data/lists/saltlist.txt",
        ):
            with self.subTest(artifact=artifact):
                self.assertIn(artifact, workflow)
        self.assertLess(
            workflow.index("Run independent correctness and false-positive suite"),
            workflow.index("Upload Artifact"),
        )
