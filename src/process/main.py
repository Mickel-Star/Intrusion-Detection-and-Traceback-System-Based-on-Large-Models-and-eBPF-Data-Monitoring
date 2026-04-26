#!/usr/bin/env python3
"""
基于Tracee的溯源入侵检测系统主脚本

该脚本仅保留论文主链路：
1) BBK 基线构建（Streaming Reduction + 频次/支持度）
2) TIK 构建（MITRE 容器相关技术 + ASG paths + Doc2Vec）
3) 检测与调查（稀有路径 + TIK 检索 + 逻辑链重构 + LLM 报告）
"""

import argparse
import logging
import os
import sys
import signal

from src.common.defaults import (
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_BBK_TRAIN_WINDOW_SECONDS,
    DEFAULT_TOP_EVIDENCE_ITEMS,
    DEFAULT_WINDOW_SECONDS,
)

# 禁用 ChromaDB 的遥测功能以防止网络超时
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_TELEMETRY_IMPL"] = "ct_none"

os.makedirs("logs", exist_ok=True)

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join("logs", "drsec.log")),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

def setup_directories() -> None:
    """设置必要的目录结构"""
    directories = [
        'data/raw',
        'data/processed',
        'data/kb',
        'data/kb/vector_db',
        'logs'
    ]
    
    for dir_path in directories:
        os.makedirs(dir_path, exist_ok=True)
        logger.info(f"已创建目录: {dir_path}")


def _short_container_id(container_id: str) -> str:
    value = str(container_id or "").strip()
    return value[:12] if value else "unknown"


def _print_window_alert_summary(alert, max_processes: int = DEFAULT_TOP_EVIDENCE_ITEMS, prefix: str = "") -> None:
    window_file = alert.window_file or f"{alert.window_id}.json"
    print(
        f"{prefix}window={alert.window_id} file={window_file} "
        f"score={float(alert.window_score):.3f} threshold={float(alert.threshold):.3f} "
        f"suspicious_processes={int(alert.suspicious_process_count)}"
    )
    if alert.impacted_containers:
        containers = ", ".join([_short_container_id(item) for item in alert.impacted_containers[:DEFAULT_TOP_EVIDENCE_ITEMS]])
        print(f"{prefix}containers={containers}")
    if alert.top_processes:
        print(f"{prefix}top_processes:")
        for item in alert.top_processes[: int(max_processes)]:
            print(
                f"{prefix}- pid={item.get('pid')} container={_short_container_id(item.get('container_id') or '')} "
                f"name={item.get('display_name') or 'unknown'} score={float(item.get('process_score', 0.0)):.3f}"
            )
    if alert.top_rare_paths:
        print(f"{prefix}top_rare_paths:")
        for rp in alert.top_rare_paths[:DEFAULT_TOP_EVIDENCE_ITEMS]:
            print(f"{prefix}- score={float(rp.get('score', 0.0)):.3f} path={str(rp.get('text') or '')[:160]}")

def main() -> None:
    """主函数"""
    parser = argparse.ArgumentParser(description='DRSEC：基于溯源图与知识库的容器异常检测')
    
    # 子命令
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # analyze 命令
    analyze_parser = subparsers.add_parser('analyze', help='分析Tracee日志中的可疑行为')
    analyze_parser.add_argument('log_file', help='Tracee日志文件路径')
    analyze_parser.add_argument('--threshold', type=float, default=DEFAULT_ALERT_THRESHOLD, help='窗口告警阈值（窗口分数，0-1）')
    analyze_parser.add_argument('--window-seconds', type=int, default=DEFAULT_WINDOW_SECONDS, help='窗口长度（秒）')
    analyze_parser.add_argument('--debug-dump-dir', default='data/processed/debug', help='调试信息输出目录')
    analyze_parser.add_argument('--print-attack-graph', action='store_true', default=True, help='打印攻击溯源图重构结果')
    analyze_parser.add_argument('--print-llm-context', action='store_true', default=True, help='打印输入给LLM的上下文（截断展示）')
    analyze_parser.add_argument('--print-process-details', action='store_true', default=False, help='打印窗口内的进程证据明细')
    analyze_parser.add_argument('--max-attack-graph-edges', type=int, default=80, help='攻击溯源图最多打印多少条边')
    analyze_parser.add_argument('--max-prompt-chars', type=int, default=2000, help='LLM上下文最多打印多少字符（其余写入文件）')
    analyze_parser.add_argument('--persist-windows-dir', default='data/processed/windows', help='持久化窗口图的输出目录')

    # build_tik 命令
    build_tik_parser = subparsers.add_parser('build_tik', help='构建 TIK（Threat Intelligence Knowledge）向量库')

    # build_bbk 命令
    build_bbk_parser = subparsers.add_parser('build_bbk', help='构建/更新 BBK（Benign Behavior Knowledge）基线库')
    build_bbk_parser.add_argument('log_file', nargs='?', default='', help='可选：单个良性Tracee日志文件路径（兼容 bootstrap 模式）')
    build_bbk_parser.add_argument('--logs-dir', default='', help='推荐：benign corpus 目录，结构为 data/benign_corpus/<run_id>/trace.log')
    build_bbk_parser.add_argument('--window-seconds', type=int, default=DEFAULT_BBK_TRAIN_WINDOW_SECONDS, help='训练窗口长度（秒，默认 10s）')
    build_bbk_parser.add_argument('--persist-windows-dir', default='', help='可选：持久化窗口图的输出目录')

    build_ark_parser = subparsers.add_parser('build_ark', help='构建 ARK（Attack Representation Knowledge）逻辑图')

    replay_parser = subparsers.add_parser('replay', help='从已持久化的窗口图回放并执行检测')
    replay_parser.add_argument('windows_dir', help='窗口图目录（window_*.json）')
    replay_parser.add_argument('--threshold', type=float, default=DEFAULT_ALERT_THRESHOLD, help='窗口告警阈值（窗口分数，0-1）')
    replay_parser.add_argument('--debug-dump-dir', default='data/processed/debug', help='调试信息输出目录')
    replay_parser.add_argument('--print-process-details', action='store_true', default=False, help='打印窗口内的进程证据明细')
    replay_parser.add_argument('--max-attack-graph-edges', type=int, default=80, help='攻击溯源图最多打印多少条边')
    replay_parser.add_argument('--max-prompt-chars', type=int, default=2000, help='LLM上下文最多打印多少字符（其余写入文件）')

    realtime_parser = subparsers.add_parser('realtime', help='实时监控：增量读取 Tracee 输出并窗口检测')
    realtime_parser.add_argument('log_file', help='Tracee 输出文件路径（持续增长）')
    realtime_parser.add_argument('--threshold', type=float, default=DEFAULT_ALERT_THRESHOLD, help='窗口告警阈值（窗口分数，0-1）')
    realtime_parser.add_argument('--window-seconds', type=int, default=DEFAULT_WINDOW_SECONDS, help='窗口长度（秒）')
    realtime_parser.add_argument('--poll-interval', type=float, default=0.2, help='轮询间隔（秒）')
    realtime_parser.add_argument('--start-at-end', action='store_true', default=True, help='从文件末尾开始追踪（默认）')
    realtime_parser.add_argument('--start-from-begin', action='store_true', default=False, help='从文件开头回放并实时追踪')
    realtime_parser.add_argument('--max-alerts-per-window', type=int, default=1, help='兼容参数：V1 固定每个窗口最多输出 1 条窗口告警')
    realtime_parser.add_argument('--max-process-evidence', type=int, default=DEFAULT_TOP_EVIDENCE_ITEMS, help='每条窗口告警最多打印多少个 top processes')
    realtime_parser.add_argument('--no-llm', action='store_true', default=True, help='默认不调用LLM，仅输出告警与稀有路径')
    realtime_parser.add_argument('--with-llm', action='store_true', default=False, help='启用LLM生成报告（可能较慢）')
    realtime_parser.add_argument('--debug-dump-dir', default='data/processed/realtime_debug', help='调试信息输出目录')
    realtime_parser.add_argument('--persist-windows-dir', default='data/processed/realtime_windows', help='持久化窗口图的输出目录')
    realtime_parser.add_argument('--max-attack-graph-edges', type=int, default=80, help='攻击溯源图最多打印多少条边')
    realtime_parser.add_argument('--max-windows', type=int, default=0, help='可选：最多处理多少个窗口后退出（0表示不限制）')
    
    # setup 命令
    setup_parser = subparsers.add_parser('setup', help='设置必要的目录结构')
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return
    
    logger.info(f"执行命令: {args.command}")
    
    if args.command == 'setup':
        setup_directories()
        logger.info("目录结构设置完成")

    elif args.command == 'analyze':
        from src.analysis.report_generator import AnalysisEngine
        
        engine = AnalysisEngine()
        print(f"\n🔍 正在分析日志文件: {args.log_file}")
        print(f"   阈值: {args.threshold}")
        print(f"   窗口: {int(args.window_seconds)}s")
        
        alerts = engine.detect_window_alerts(
            args.log_file,
            args.threshold,
            persist_windows_dir=(args.persist_windows_dir or None),
            window_seconds=int(args.window_seconds),
        )
        
        if not alerts:
            print("\n✅ 未发现窗口告警（基于当前阈值）")
            return

        print(f"\n⚠️ 发现 {len(alerts)} 个窗口告警:")
        for i, alert in enumerate(alerts, start=1):
            print(
                f"\n--- 窗口告警 #{i} "
                f"(window={alert.window_id}, score={float(alert.window_score):.3f}, file={alert.window_file or 'n/a'}) ---"
            )
            _print_window_alert_summary(alert, max_processes=int(DEFAULT_TOP_EVIDENCE_ITEMS))
            if bool(args.print_process_details):
                for proc in alert.top_processes[:DEFAULT_TOP_EVIDENCE_ITEMS]:
                    graph_context = str(proc.get("graph_context") or "").strip()
                    if graph_context:
                        print("\nGraph Context:")
                        print(graph_context)

            print("\n🤖 正在生成窗口级分析报告...")
            report, debug = engine.analyze_window_alert(
                alert,
                dump_dir=args.debug_dump_dir,
                return_debug=True,
                max_attack_graph_edges_print=int(args.max_attack_graph_edges),
            )

            if args.print_attack_graph and debug.get("attack_provenance_graph_edges"):
                print("\n" + "-" * 50)
                print(debug["attack_provenance_graph_edges"])
                print("-" * 50)

            prompt_for_print = debug.get("llm_stage3_prompt") or debug.get("prompt")
            if args.print_llm_context and prompt_for_print:
                p = str(prompt_for_print)
                head = p[: int(args.max_prompt_chars)]
                print("\n" + "-" * 50)
                print("LLM Prompt (truncated):")
                print(head)
                if len(p) > int(args.max_prompt_chars):
                    print(f"... (truncated, full prompt saved under {args.debug_dump_dir})")
                print("-" * 50)
            
            print("\n" + "="*50)
            print("分析报告")
            print("="*50)
            print(report)
            print("="*50)

    elif args.command == 'build_tik':
        from src.knowledge.kb_builders import build_tik
        build_tik()
        print("\n✅ TIK 知识库构建完成（tik_knowledge）")

    elif args.command == 'build_bbk':
        from src.knowledge.kb_builders import build_bbk
        build_bbk(
            args.log_file,
            logs_dir=str(args.logs_dir or ""),
            persist_windows_dir=str(args.persist_windows_dir or ""),
            window_seconds=int(args.window_seconds),
        )

    elif args.command == 'build_ark':
        from src.knowledge.kb_builders import build_ark
        build_ark()

    elif args.command == 'replay':
        from src.analysis.report_generator import AnalysisEngine
        engine = AnalysisEngine()
        alerts = engine.detect_window_alerts_from_windows(args.windows_dir, args.threshold)
        if not alerts:
            print("\n✅ 未发现窗口告警（基于当前阈值）")
            return
        print(f"\n⚠️ 发现 {len(alerts)} 个窗口告警:")
        for i, alert in enumerate(alerts, start=1):
            print(
                f"\n--- 窗口告警 #{i} "
                f"(window={alert.window_id}, score={float(alert.window_score):.3f}, file={alert.window_file or 'n/a'}) ---"
            )
            _print_window_alert_summary(alert, max_processes=int(DEFAULT_TOP_EVIDENCE_ITEMS))
            if bool(args.print_process_details):
                for proc in alert.top_processes[:DEFAULT_TOP_EVIDENCE_ITEMS]:
                    graph_context = str(proc.get("graph_context") or "").strip()
                    if graph_context:
                        print("\nGraph Context:")
                        print(graph_context)
            print("\n🤖 正在生成窗口级分析报告...")
            report, debug = engine.analyze_window_alert(
                alert,
                dump_dir=args.debug_dump_dir,
                return_debug=True,
                max_attack_graph_edges_print=int(args.max_attack_graph_edges),
            )
            prompt_for_print = debug.get("llm_stage3_prompt") or debug.get("prompt")
            if prompt_for_print:
                p = str(prompt_for_print)
                head = p[: int(args.max_prompt_chars)]
                print("\n" + "-" * 50)
                print("LLM Prompt (truncated):")
                print(head)
                if len(p) > int(args.max_prompt_chars):
                    print(f"... (truncated, full prompt saved under {args.debug_dump_dir})")
                print("-" * 50)
            print("\n" + "="*50)
            print("分析报告")
            print("="*50)
            print(report)
            print("="*50)

    elif args.command == 'realtime':
        from src.analysis.report_generator import AnalysisEngine
        from src.process.realtime_monitor import RealtimeConfig, iter_realtime_windows
        from src.process.window_io import dump_window_graph

        engine = AnalysisEngine()
        os.makedirs(args.debug_dump_dir, exist_ok=True)
        os.makedirs(args.persist_windows_dir, exist_ok=True)
        start_at_end = True
        if bool(args.start_from_begin):
            start_at_end = False
        if bool(args.with_llm):
            args.no_llm = False

        cfg = RealtimeConfig(
            window_seconds=int(args.window_seconds),
            poll_interval_seconds=float(args.poll_interval),
            start_at_end=bool(start_at_end),
        )

        window_idx = 0
        print(f"🔎 Realtime monitoring: file={args.log_file} window={cfg.window_seconds}s threshold={float(args.threshold)}")
        for g, metas in iter_realtime_windows(args.log_file, cfg):
            window_idx += 1
            win_name = f"window_{window_idx:04d}.json"
            win_path = os.path.join(args.persist_windows_dir, win_name)
            dump_window_graph(win_path, g)

            alerts = engine.detect_window_alerts_in_window(g, float(args.threshold), window_hint=win_name)
            if not alerts:
                print(f"[window#{window_idx}] ✅ no window alerts")
                if int(args.max_windows) > 0 and window_idx >= int(args.max_windows):
                    break
                continue

            alert = alerts[0]
            print(
                f"[window#{window_idx}] ⚠️ window_alert score={float(alert.window_score):.3f} "
                f"saved={win_name} suspicious_processes={int(alert.suspicious_process_count)}"
            )
            _print_window_alert_summary(
                alert,
                max_processes=int(args.max_process_evidence),
                prefix="  ",
            )

            if bool(args.no_llm):
                if int(args.max_windows) > 0 and window_idx >= int(args.max_windows):
                    break
                continue

            print(f"\n🤖 report window={alert.window_id} score={float(alert.window_score):.3f} ...")
            report, _debug = engine.analyze_window_alert(
                alert,
                dump_dir=args.debug_dump_dir,
                return_debug=True,
                max_attack_graph_edges_print=int(args.max_attack_graph_edges),
            )
            print(report)
            if int(args.max_windows) > 0 and window_idx >= int(args.max_windows):
                break

if __name__ == "__main__":
    main()
