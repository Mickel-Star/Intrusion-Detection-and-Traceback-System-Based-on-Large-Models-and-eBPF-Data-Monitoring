#!/usr/bin/env python3
"""
Tracee日志解析器
用于将Tracee生成的原始日志转换为结构化数据
"""

import os
import re
import json
from datetime import datetime
from typing import List, Dict, Any

class TraceeLogParser:
    """Tracee日志解析器类"""
    
    def __init__(self):
        self.log_pattern = re.compile(r'^(\d{2}:\d{2}:\d{2}:\d{6})\s+(\d+)\s+([^\s]+)\s+(\d+)\s+(\d+)\s+([-\d]+)\s+([^\s]+)\s+(.*)$')
        self.log_pattern_container = re.compile(
            r'^(\d{2}:\d{2}:\d{2}:\d{6})\s+([0-9a-fA-F]{6,})\s+([^\s]+)\s+(\d+)\s+([^\s]+)\s+(\d+)\s*/\s*(\d+)\s+(\d+)\s*/\s*(\d+)\s+([-\d]+)\s+([^\s]+)\s+(.*)$'
        )
        self.args_pattern = re.compile(r'([^,:\s]+):\s*([^,\n]+)')
    
    def parse_log_line(self, line: str) -> Dict[str, Any]:
        """解析单行Tracee日志"""
        if line.startswith('TIME'):
            return None  # 跳过表头行
        
        match = self.log_pattern_container.match(line)
        if match:
            (
                time_str,
                container_id,
                image,
                uid,
                comm,
                pid_container,
                pid_host,
                tid_container,
                tid_host,
                ret,
                event,
                args_str,
            ) = match.groups()
            timestamp = self._parse_timestamp(time_str)
            args = self._parse_args(args_str)
            structured_data = {
                "timestamp": timestamp,
                "uid": int(uid),
                "comm": comm.strip(),
                "pid": int(pid_host),
                "tid": int(tid_host),
                "ret": int(ret),
                "event": event.strip(),
                "args": args,
                "container_id": container_id,
                "container_image": image,
                "container_pid": int(pid_container),
                "container_tid": int(tid_container),
            }
            return structured_data

        match = self.log_pattern.match(line)
        if not match:
            return None

        time_str, uid, comm, pid, tid, ret, event, args_str = match.groups()
        
        # 解析时间
        timestamp = self._parse_timestamp(time_str)
        
        # 解析参数
        args = self._parse_args(args_str)
        
        # 构建结构化数据
        structured_data = {
            'timestamp': timestamp,
            'uid': int(uid),
            'comm': comm.strip(),
            'pid': int(pid),
            'tid': int(tid),
            'ret': int(ret),
            'event': event.strip(),
            'args': args
        }
        
        # 提取 Kubernetes 上下文（如果存在于参数中）
        # Tracee 有时会将 k8s 信息放在 args 或 context 中
        # 这里尝试从 args 中提取常见的 k8s 字段
        if 'pod_name' in args:
            structured_data['pod_name'] = args['pod_name']
        if 'container_id' in args:
            structured_data['container_id'] = args['container_id']
        
        return structured_data
    
    def _parse_timestamp(self, time_str: str) -> float:
        """解析时间戳字符串"""
        # 格式: HH:MM:SS:ssssss
        dt = datetime.strptime(time_str, '%H:%M:%S:%f')
        # 转换为当天的时间戳（秒）
        return dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1000000
    
    def _parse_json_line(self, json_log: Dict[str, Any]) -> Dict[str, Any]:
        """Parses a single JSON log entry from Tracee (JSON output mode)."""
        try:
            # Tracee JSON format usually has: timestamp, processName, processId, eventName, args, etc.
            # Adaptation logic to match our internal structure
            
            # Timestamp (nanoseconds -> seconds)
            timestamp = json_log.get('timestamp', 0) / 1e9
            
            structured_data = {
                'timestamp': timestamp,
                'uid': json_log.get('userId', 0),
                'comm': json_log.get('processName', 'unknown'),
                'pid': json_log.get('processId', 0),
                'tid': json_log.get('threadId', 0),
                'ret': json_log.get('returnValue', 0),
                'event': json_log.get('eventName', 'unknown'),
                'args': {}
            }
            
            # Flatten args
            if 'args' in json_log:
                for arg in json_log['args']:
                    key = arg.get('name')
                    value = arg.get('value')
                    if key:
                        structured_data['args'][key] = value
            
            # Kubernetes context
            if 'kubernetes' in json_log:
                k8s = json_log['kubernetes']
                if 'podName' in k8s:
                    structured_data['pod_name'] = k8s['podName']
                if 'containerId' in k8s:
                    structured_data['container_id'] = k8s['containerId']
            
            return structured_data
        except Exception as e:
            # print(f"Error parsing JSON log: {e}")
            return None
    
    def _parse_args(self, args_str: str) -> Dict[str, Any]:
        """解析事件参数。"""
        args = {}

        # Tracee table 输出会把 socket 地址渲染成 `remote_addr: map[...]`。
        # 先抽取这些 map 值，再解析剩余的普通 key/value，避免 map 前缀被误当成一个长 key。
        remaining = str(args_str or "")
        for match in list(re.finditer(r"([A-Za-z0-9_]+):\s*map\[(.*?)\]", remaining)):
            key = match.group(1).strip()
            map_content = match.group(2)
            map_args = {}
            for item_key, value in re.findall(r"([A-Za-z0-9_]+):([^\s\]]+)", map_content):
                map_args[item_key.strip()] = value.strip().rstrip(",")
            if key:
                args[key] = map_args

        remaining = re.sub(r"([A-Za-z0-9_]+):\s*map\[(.*?)\]", r"\1: ", remaining)

        # 处理普通键值对参数
        for match in self.args_pattern.finditer(remaining):
            key, value = match.groups()
            if key.strip() not in args:
                args[key.strip()] = value.strip()

        return args

    def parse_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """解析整个日志文件"""
        structured_logs = []
        
        if not os.path.exists(file_path):
            print(f"Error: Log file not found at {file_path}")
            return []

        is_json = file_path.endswith(".json") or file_path.endswith(".jsonl")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if is_json or line.startswith("{"):
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    parsed = self._parse_json_line(obj)
                else:
                    parsed = self.parse_log_line(line)

                if parsed:
                    structured_logs.append(parsed)
        
        return structured_logs

if __name__ == "__main__":
    # 测试解析器
    parser = TraceeLogParser()
    test_file = '../../data/raw/tracee.log'
    if os.path.exists(test_file):
        logs = parser.parse_log_file(test_file)
        print(f"解析了 {len(logs)} 条日志记录")
        if logs:
            print("\n第一条记录:")
            for key, value in logs[0].items():
                print(f"  {key}: {value}")
    else:
        print(f"Test file not found: {test_file}")
