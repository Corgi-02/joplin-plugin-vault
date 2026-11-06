import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description='Joplin 插件保险箱')
    parser.add_argument('--inspect', metavar='PROFILE', help='只读检查配置目录并输出不含设置值的清单')
    parser.add_argument('--output', help='将检查结果写入指定 JSON 文件')
    args = parser.parse_args()
    if args.inspect:
        from vault.core import inventory, Layout
        from vault.paths import default_joplin_exe
        result, _ = inventory(Layout.discover(args.inspect), default_joplin_exe())
        summary = {k: result[k] for k in ['format', 'version', 'plugins', 'warnings']}
        summary['database_setting_count'] = len(result['settings_database'])
        text = json.dumps(summary, ensure_ascii=False, indent=2)
        if args.output:
            from pathlib import Path
            Path(args.output).write_text(text, encoding='utf-8')
        elif sys.stdout:
            print(text)
        return
    from vault.ui import run
    run()


if __name__ == '__main__':
    main()
