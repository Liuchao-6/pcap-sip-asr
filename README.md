# pcap SIP/RTP 批量录音导出工具

这个工具批量读取 `pcapsipdump` 生成的 `.pcap`、`.pcapng` 或 `.cap` 文件：

- 如果抓包中存在 `SIP/2.0 200 OK`，且同一响应的 `CSeq` 方法是 `INVITE`，判定为“已接通”。
- 没有发现上述响应时判定为“未接通”。
- 将 G.711 PCMA（Payload Type 8）和 PCMU（Payload Type 0）RTP 音频合成为单声道 WAV。
- 输出 `导出报告.csv`，便于按文件查看状态、录音时长和失败原因。

工具只读取原抓包，不移动或修改原文件。文件名会原样保留，例如 `时间-主叫-被叫-id.pcap` 会导出为 `时间-主叫-被叫-id.wav`。

## 环境

需要 Python 3.10 或更高版本，不需要安装 `tshark`、`ffmpeg` 或第三方 Python 包。

## 最简单的使用方法（Windows）

把装有抓包的目录拖到 `导出录音.bat` 上。默认处理全部抓包，输出在该抓包目录下的 `wav_output`：

```text
wav_output/
  已接通/
  未接通/
  导出报告.csv
```

只导出未接通通话，可在 PowerShell 或 CMD 中运行：

```powershell
.\导出录音.bat "D:\抓包目录" unanswered
```

## Python 命令行

```powershell
# 全部导出
py -3 .\pcapsip2wav.py "D:\抓包目录" -o "D:\录音输出"

# 只导出未接通通话的媒体（如 183 Early Media、彩铃或失败提示音）
py -3 .\pcapsip2wav.py "D:\抓包目录" -o "D:\录音输出" --status unanswered

# 只导出已接通通话
py -3 .\pcapsip2wav.py "D:\抓包目录" -o "D:\录音输出" --status answered

# 只扫描当前目录，不递归扫描子目录
py -3 .\pcapsip2wav.py "D:\抓包目录" --no-recursive
```

也可以把单个抓包文件作为输入。

## 判定和格式边界

- “已接通”严格指抓包明文中出现 INVITE 事务的 `200 OK`。REGISTER、OPTIONS、BYE 等事务的 `200 OK` 不会误判为接通。
- 当前内置解码 PCMA/PCMU。若报告显示其他 RTP Payload Type，通常是 G.722、AMR、Opus 等编码，需要增加相应解码器后才能导出。
- 加密媒体 SRTP 无法直接解码；需要相应密钥及额外解密流程。
- 未接通抓包只有在实际存在 RTP Early Media 时才会生成 WAV；纯振铃或纯信令抓包会在报告中写明“未发现可导出的 G.711 RTP 媒体流”。
- 如果 pcap/pcapng 仅在文件末尾被截断，工具会忽略最后一个不完整数据包并处理此前的完整内容，同时在结果中标注“已忽略尾部截断数据”；文件头损坏时仍无法处理。
