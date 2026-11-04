# pcap SIP/RTP 批量录音导出工具

这个工具可以批量读取 `pcapsipdump` 生成的 `.pcap`、`.pcapng` 或 `.cap` 文件，也可以直接识别单个 WAV 文件：

- 如果抓包中存在 `SIP/2.0 200 OK`，且同一响应的 `CSeq` 方法是 `INVITE`，判定为“已接通”。
- 没有发现上述响应时判定为“未接通”。
- 将双向 G.711 PCMA（Payload Type 8）和 PCMU（Payload Type 0）RTP 音频默认导出为双声道 WAV，并生成左右单声道文件供独立识别和翻译。
- 输出 `导出报告.csv`，便于按文件查看状态、录音时长和失败原因。
- 无需启用 ASR 即可按 RTP 方向统计丢包、连续缺口、抖动、乱序和重复包，并在报告中标记是否疑似卡顿。
- 可选使用本地 `faster-whisper` 对未接通、已接通或全部录音执行多语言 ASR，自动检测语言并默认翻译成中文。
- 指定单个 WAV 时不再解析 SIP，也不复制或修改原文件，直接执行 ASR 并生成识别报告。

工具只读取原抓包，不移动或修改原文件。文件名会原样保留，例如 `时间-主叫-被叫-id.pcap` 会导出为 `时间-主叫-被叫-id.wav`。

## 环境

需要 Python 3.10 或更高版本。仅导出抓包录音时不需要安装 `tshark`、`ffmpeg` 或第三方 Python 包；使用 ASR 和翻译时需要安装后文列出的依赖。

## 最简单的使用方法（Windows）

把装有抓包的目录拖到 `导出录音.bat` 上。默认处理全部抓包，输出在该抓包目录下的 `wav_output`：

```text
wav_output/
  已接通/
    声道/
  未接通/
    声道/
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

## 参数说明

```text
python3.10 pcapsip2wav.py INPUT [-o OUTPUT]
                               [--status {all,answered,unanswered}]
                               [--no-recursive]
                               [--channel-mode {separate,mixed}]
                               [--asr]
                               [--asr-status {all,answered,unanswered}]
                               [--asr-model MODEL]
                               [--asr-model-dir DIR]
                               [--asr-language LANGUAGE]
                               [--translate-language LANGUAGE]
                               [--no-translate]
                               [--asr-similarity 0-1]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-h`, `--help` | - | 显示命令帮助并退出。 |
| `INPUT` | 必填 | 抓包目录、单个 `.pcap`、`.pcapng`、`.cap` 文件，或单个 `.wav` 文件。 |
| `-o`, `--output` | `wav_output` | 输出目录。 |
| `--status` | `all` | 控制导出范围：`all` 全部、`answered` 仅已接通、`unanswered` 仅未接通。 |
| `--no-recursive` | 关闭 | 输入是目录时只扫描当前目录，不扫描子目录。 |
| `--channel-mode` | `separate` | `separate` 左右声道分别导出、识别和翻译；`mixed` 合并声道后处理。 |
| `--asr` | 关闭 | 启用 ASR；未指定时只导出 WAV，不加载模型。 |
| `--asr-status` | `unanswered` | 控制 ASR 范围：`all` 全部、`answered` 仅已接通、`unanswered` 仅未接通。只在使用 `--asr` 时生效。 |
| `--asr-model` | `small` | faster-whisper 模型名称或本地模型目录。 |
| `--asr-model-dir` | 未指定 | 模型下载及缓存目录。 |
| `--asr-language` | `auto` | `auto` 自动检测语言；也可用 `zh`、`es`、`en` 等代码强制指定语言。 |
| `--translate-language` | `zh` | 翻译目标语言代码；默认翻译成中文，也可指定 `en`、`es`、`ja` 等。 |
| `--no-translate` | 关闭 | 只保留原语言识别文本，不执行翻译。 |
| `--asr-similarity` | `0.82` | 识别文本聚类阈值，范围 `0` 到 `1`；越高越严格。 |

`--status` 和 `--asr-status` 的职责不同：前者决定哪些抓包生成 WAV，后者决定对其中哪些 WAV 执行 ASR。例如使用 `--status unanswered --asr-status answered` 时，没有已接通 WAV 可供识别。

直接输入单个 WAV 时必须使用 `--asr`。此时不判断 SIP 接通状态，`--status`、`--asr-status` 和 `--no-recursive` 均不参与筛选；报告中的“接通状态”显示为“直接WAV”。

默认 `--channel-mode separate`：抓包中恰好有两个 RTP 方向时，主 WAV 为左右双声道，`声道` 子目录中的左右单声道 WAV 分别执行 ASR 和翻译，报告按声道各写一行。只有一个 RTP 方向时按单声道处理；超过两个方向时为避免丢音，自动回退到混合模式并在报告中注明。左右声道代表两个媒体方向，不自动等同于主叫和被叫。

不需要区分左右声道时使用：

```bash
python3.10 pcapsip2wav.py /data/pcap -o /data/wav_output \
  --channel-mode mixed --asr
```

## RTP 卡顿检测

卡顿检测始终启用，不依赖 `--asr`。最简单的检查命令：

```bash
python3.10 pcapsip2wav.py /data/pcap -o /data/wav_output
```

`导出报告.csv` 按声道提供 RTP 方向、编码、有效包数、推测丢包数、丢包事件数、丢包率、最长连续缺口、RFC 3550 抖动、乱序包数、重复包数、“疑似卡顿”和“卡顿依据”。当前任一条件满足即标记为“是”：

- 丢包率达到 `1%`；
- 单次连续音频缺口达到 `40 ms`；
- RTP 抖动达到 `30 ms`。

直接输入 WAV 时没有 RTP 序号、时间戳和网络到达时间，报告标记“无法判断（无RTP）”。抓包结果反映该采集点观察到的 RTP 风险；终端 jitter buffer、PLC 补偿、抓包自身漏包及采集位置都可能影响用户实际听感，因此“疑似卡顿”不是最终听感结论。

## CentOS 7 提示音识别

安装 Python 3.10 后，在可联网的 CentOS 7.9 x86_64 服务器安装 ASR 依赖：

```bash
python3.10 -m pip install -r requirements-asr-centos7.txt
```

ASR 依赖中已包含本地 Argos 翻译引擎。第一次翻译到中文或其他非英语目标语言时，会联网下载英语到目标语言的 Argos 模型包，后续使用本地模型。音频、识别原文和翻译内容不会发送给在线翻译服务。

直接识别指定 WAV：

```bash
python3.10 pcapsip2wav.py /data/audio/call.wav -o /data/asr_output \
  --asr --asr-model /data/asr-models/faster-whisper-small
```

识别内容写入 `/data/asr_output/导出报告.csv`，相似内容分类写入 `/data/asr_output/提示音分类汇总.csv`，原 WAV 保持不变。

直接输入双声道 WAV 时，默认在输出目录的 `直接WAV/声道` 中生成左右单声道文件并分别识别、翻译。使用 `--channel-mode mixed` 时不拆分，由 faster-whisper 混合声道后只生成一条识别结果。

自动检测西班牙语并翻译成中文：

```bash
python3.10 pcapsip2wav.py /data/audio/spanish.wav -o /data/asr_output \
  --asr --asr-language auto \
  --asr-model /data/asr-models/faster-whisper-small
```

中文是默认翻译目标，因此不需要添加翻译参数。处理流程为：Whisper 自动检测语言并输出西班牙语原文；外语音频再由 Whisper 翻译成英文中间文本；Argos 本地模型将英文翻译成中文。报告记录检测语言、置信度、识别原文、翻译目标语言、翻译文本、ASR 状态及翻译状态。

翻译成其他语言时指定目标语言代码，例如翻译成英语：

```bash
python3.10 pcapsip2wav.py /data/audio/spanish.wav -o /data/asr_output \
  --asr --translate-language en \
  --asr-model /data/asr-models/faster-whisper-small
```

只识别西班牙语原文、不翻译：

```bash
python3.10 pcapsip2wav.py /data/audio/spanish.wav -o /data/asr_output \
  --asr --no-translate \
  --asr-model /data/asr-models/faster-whisper-small
```

只导出未接通录音并识别中文提示音：

```bash
python3.10 pcapsip2wav.py /data/pcap -o /data/wav_output \
  --status unanswered --asr --asr-status unanswered
```

只导出并识别已接通录音：

```bash
python3.10 pcapsip2wav.py /data/pcap -o /data/wav_output \
  --status answered --asr --asr-status answered
```

导出并识别全部录音：

```bash
python3.10 pcapsip2wav.py /data/pcap -o /data/wav_output \
  --status all --asr --asr-status all
```

默认使用 CPU、`int8` 和 `small` 模型。首次运行会联网下载模型，后续使用本地缓存。可指定缓存目录或更高精度模型：

```bash
python3.10 pcapsip2wav.py /data/pcap -o /data/wav_output --status unanswered --asr \
  --asr-model medium --asr-model-dir /data/asr-models
```

`small` 适合先验证速度和识别效果；`medium` 通常更准确，但模型更大、CPU 识别更慢。ASR 只处理符合 `--asr-status` 且成功生成 WAV 的文件。默认自动检测语言；已知音频全部是中文时，可使用 `--asr-language zh` 降低短提示音的语言误判概率。单条识别或翻译失败会写入对应状态列，不影响其他文件继续处理。

识别结束后，工具会自动合并内容相同或相似的提示音：忽略空格、标点、全角半角以及具体数字差异，并按文本相似度聚类。`导出报告.csv` 中会增加“提示音分类”，输出目录还会生成 `提示音分类汇总.csv`，按数量列出每类提示音的代表内容和识别文本变体。

默认相似度阈值是 `0.82`。阈值越低，越容易把不同内容合并；阈值越高，分类越严格。可按实际识别效果调整：

```bash
python3.10 pcapsip2wav.py /data/pcap -o /data/wav_output --status unanswered --asr \
  --asr-model /data/asr-models/faster-whisper-small --asr-similarity 0.82
```

## 判定和格式边界

- “已接通”严格指抓包明文中出现 INVITE 事务的 `200 OK`。REGISTER、OPTIONS、BYE 等事务的 `200 OK` 不会误判为接通。
- 当前内置解码 PCMA/PCMU。若报告显示其他 RTP Payload Type，通常是 G.722、AMR、Opus 等编码，需要增加相应解码器后才能导出。
- 加密媒体 SRTP 无法直接解码；需要相应密钥及额外解密流程。
- 未接通抓包只有在实际存在 RTP Early Media 时才会生成 WAV；纯振铃或纯信令抓包会在报告中写明“未发现可导出的 G.711 RTP 媒体流”。
- 如果 pcap/pcapng 仅在文件末尾被截断，工具会忽略最后一个不完整数据包并处理此前的完整内容，同时在结果中标注“已忽略尾部截断数据”；文件头损坏时仍无法处理。
