"""本地模型环境自检。

跑这个脚本，它会告诉你：
  1. 本机适合跑多大的模型
  2. Ollama 装了没、模型拉没拉
  3. 已经有的模型，工具调用能力实测如何

用法：
    python tools/check_local_llm.py
    python tools/check_local_llm.py --model qwen2.5:3b
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE = "http://127.0.0.1:11434"

# 本机服务不能走代理，否则 127.0.0.1 会被代理拦截（表现为 502）
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def total_ram_gb() -> float:
    """读物理内存。不用 psutil——不为一个数字引一个依赖。"""
    if platform.system() == "Windows":
        class M(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        m = M()
        m.dwLength = ctypes.sizeof(m)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return m.ullTotalPhys / 2 ** 30
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / 1024 / 1024
    except OSError:
        pass
    return 0.0


def gpu_status() -> dict:
    """探测 NVIDIA 显卡。

    不只看 nvidia-smi 存在与否——它可能装着但驱动没加载好，
    这时会报 "Failed to initialize NVML"。必须把这种情况和「没显卡」区分开，
    否则会给出完全错误的建议（比如让有 8GB 显卡的人去跑 CPU 小模型）。
    """
    exe = None
    for cand in (r"C:\Windows\System32\nvidia-smi.exe",
                 r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"):
        if os.path.exists(cand):
            exe = cand
            break
    if not exe:
        return {"present": False}

    import subprocess
    try:
        out = subprocess.run(
            [exe, "--query-gpu=name,memory.total,driver_version,compute_cap",
             "--format=csv,noheader"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        return {"present": True, "ok": False, "error": str(exc)}

    text = (out.stdout or "") + (out.stderr or "")
    if "NVML" in text or out.returncode != 0:
        return {"present": True, "ok": False,
                "error": text.strip()[:120], "exe": exe}

    parts = [p.strip() for p in out.stdout.strip().split(",")]
    vram = 0.0
    if len(parts) >= 2:
        m = parts[1]
        try:
            vram = float(m.replace("MiB", "").replace("GiB", "").strip())
            vram = vram / 1024 if "MiB" in m else vram
        except ValueError:
            vram = 0.0
    return {
        "present": True, "ok": True,
        "name": parts[0] if parts else "?",
        "vram_gb": round(vram, 1),
        "driver": parts[2] if len(parts) > 2 else "?",
        "compute_cap": parts[3] if len(parts) > 3 else "?",
    }


def recommend_by_vram(vram_gb: float) -> list[tuple[str, str]]:
    """按显存推荐模型。参数是 q4_K_M 量化的经验值。

    判断标准：模型权重 + KV cache 要能整个放进显存，
    否则会溢出到内存，速度掉一个数量级。
    """
    if vram_gb >= 16:
        return [("qwen2.5:14b", "约 9GB，质量明显更好"),
                ("qwen2.5:7b", "约 4.7GB，快且够用")]
    if vram_gb >= 12:
        return [("qwen2.5:7b", "约 4.7GB，留足 KV cache"),
                ("qwen2.5:14b", "约 9GB，勉强但不宽松")]
    if vram_gb >= 8:
        return [("qwen2.5:7b", "约 4.7GB，8GB 显存的最佳选择，速度约 30-45 tok/s"),
                ("qwen2.5:3b", "约 2GB，更快，适合批量跑")]
    if vram_gb >= 6:
        return [("qwen2.5:3b", "约 2GB，7B 会溢出"),
                ("qwen2.5:7b", "会溢出到内存，速度掉一个数量级")]
    return [("qwen2.5:1.5b", "约 1GB，只能做最简单的判断")]


def recommend(ram_gb: float, cores: int, has_gpu: bool) -> list[tuple[str, str]]:
    """无显卡时的建议（保留兼容）。"""
    out = []
    if ram_gb >= 14:
        out.append(("qwen2.5:7b", "约 4.7GB 内存，中文好；CPU 上偏慢"))
    if ram_gb >= 7:
        out.append(("qwen2.5:3b", "约 2GB 内存，速度快"))
    if ram_gb >= 4:
        out.append(("qwen2.5:1.5b", "约 1GB，只能做最简单的判断"))
    out.append(("", "无 GPU：7B 在 CPU 上大约 5-8 tok/s，一条研判要 1-3 分钟"))
    if cores <= 4:
        out.append(("", "核心数少，推理会更慢；建议只用 3B"))
    return out


def probe(base: str = BASE) -> dict:
    try:
        with _NO_PROXY.open(f"{base}/api/tags", timeout=3) as resp:
            return {"ok": True, "data": json.loads(resp.read().decode())}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def test_tool_calling(model: str, base: str = BASE) -> dict:
    """用最小场景测模型的工具调用能力。

    只给一个工具、一个问题，看它能不能输出合法的调用。
    这是本地模型最不可靠的地方，必须先测再用。
    """
    schema = [{
        "type": "function",
        "function": {
            "name": "get_ip_info",
            "description": "查询 IP 的归属信息",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    }]
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "你是助手。需要数据时必须调用工具，不要编造。"},
            {"role": "user", "content": "帮我查一下 8.8.8.8 的归属"},
        ],
        "tools": schema,
        "temperature": 0,
        "stream": False,
    }).encode()

    req = urllib.request.Request(f"{base}/v1/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    t0 = time.time()
    try:
        with _NO_PROXY.open(req, timeout=180) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "elapsed": time.time() - t0}

    msg = (data.get("choices") or [{}])[0].get("message") or {}
    calls = msg.get("tool_calls") or []
    return {
        "ok": bool(calls),
        "calls": calls,
        "text": (msg.get("content") or "")[:200],
        "elapsed": time.time() - t0,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="本地模型环境自检")
    ap.add_argument("--model", default="qwen2.5:3b")
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--skip-test", action="store_true", help="跳过工具调用实测")
    args = ap.parse_args(argv)

    ram = total_ram_gb()
    cores = os.cpu_count() or 1
    gpu = gpu_status()

    print("=" * 62)
    print("本机")
    print("=" * 62)
    print(f"  内存   {ram:.1f} GB")
    print(f"  核心   {cores}")

    if gpu["present"] and gpu["ok"]:
        print(f"  GPU    {gpu['name']} · {gpu['vram_gb']} GB · 驱动 {gpu['driver']}")
        print(f"         计算能力 sm_{gpu['compute_cap'].replace('.', '')}")
    elif gpu["present"]:
        print("  GPU    检测到 NVIDIA 设备，但驱动未加载")
        print(f"         报错：{gpu.get('error', '')}")
    else:
        print("  GPU    无")

    print("\n建议模型")
    if gpu["present"] and gpu["ok"]:
        for name, note in recommend_by_vram(gpu["vram_gb"]):
            print(f"  · {name:<14} {note}")
    elif gpu["present"]:
        print("  先把驱动修好再选模型。显存未知时不要盲目拉大模型。")
        print("  修复步骤见下。")
    else:
        for name, note in recommend(ram, cores, False):
            if name:
                print(f"  · {name:<14} {note}")
            else:
                print(f"    {note}")

    # 显卡存在但驱动坏了：这是最需要明确指引的情况
    if gpu["present"] and not gpu["ok"]:
        print("\n" + "=" * 62)
        print("驱动问题（必须先解决）")
        print("=" * 62)
        print("  症状：nvidia-smi 报 Failed to initialize NVML")
        print("  含义：显卡在，但驱动没起来。常见于：")
        print("    1. 50 系（Blackwell）显卡搭配旧驱动 —— 需要 572.xx 以上 + CUDA 12.8")
        print("    2. 驱动更新后未重启")
        print("    3. 笔记本双显卡，独显被系统关掉")
        print("\n  处理顺序：")
        print("    a. 设备管理器看显示适配器下有没有黄色感叹号")
        print("    b. 去 NVIDIA 官网按型号下载最新驱动，安装时选「清洁安装」")
        print("    c. 无效就用 DDU 在安全模式彻底卸载，再装")
        print("    d. 重启后运行 nvidia-smi 确认能看到显卡和显存")
        print("\n  驱动修好之前，Ollama 只会用 CPU，7B 会慢到不可用。")

    print("\n" + "=" * 62)
    print("Ollama")
    print("=" * 62)
    info = probe(args.base)
    if not info["ok"]:
        print(f"  ✗ 连不上 {args.base}")
        print(f"    原因：{info['error']}")
        print("\n  安装与启动：")
        print("    1. 下载 https://ollama.com/download")
        print(f"    2. ollama pull {args.model}")
        print("    3. ollama serve   （Windows 安装后自动常驻，可跳过）")
        print("\n  装好后重跑本脚本。")
        return 1

    models = [m.get("name", "") for m in info["data"].get("models", [])]
    print(f"  ✓ 服务在跑（{args.base}）")
    if models:
        print(f"  已有模型：{', '.join(models)}")
    else:
        print("  已有模型：无")
        print(f"  先拉一个：ollama pull {args.model}")
        return 1

    if args.model not in models:
        print(f"\n  ✗ 指定的 {args.model} 不在列表里")
        print(f"    拉取：ollama pull {args.model}")
        return 1

    if args.skip_test:
        return 0

    print("\n" + "=" * 62)
    print("工具调用能力实测")
    print("=" * 62)
    print(f"  模型：{args.model}（首次加载会慢，耐心等）")
    r = test_tool_calling(args.model, args.base)
    if not r["ok"]:
        print(f"  ✗ 没能正确调用工具（{r['elapsed']:.1f}s）")
        if r.get("text"):
            print(f"    模型输出：{r['text']}")
        print("\n  这不代表模型不能用，改用文本协议模式：")
        print("    python -m agents.app chat --index 0 --local --mode text")
        return 2

    print(f"  ✓ 能正确调用工具（{r['elapsed']:.1f}s）")
    for c in r["calls"]:
        fn = c.get("function", {})
        print(f"    -> {fn.get('name')}({fn.get('arguments')})")
    print("\n  这个模型可以直接用 tools 模式：")
    print("    python -m agents.app chat --index 0 --local --mode tools")
    return 0


def _has_nvidia_unused() -> bool:
    if os.name != "nt":
        return os.path.exists("/proc/driver/nvidia/version")
    try:
        import subprocess
        subprocess.run(["nvidia-smi"], capture_output=True, check=True, timeout=5)
        return True
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    raise SystemExit(main())
