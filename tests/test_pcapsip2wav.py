import csv
import socket
import struct
import tempfile
import unittest
import wave
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pcapsip2wav as tool


def udp_frame(payload: bytes, sport: int, dport: int, src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20 + len(udp))
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    ethernet = b"\x00" * 12 + b"\x08\x00"
    return ethernet + bytes(ip) + udp


def tcp_frame(payload: bytes, sequence: int, sport: int = 5060, dport: int = 5060) -> bytes:
    tcp = bytearray(20)
    struct.pack_into("!HHI", tcp, 0, sport, dport, sequence)
    tcp[12] = 0x50
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20 + len(tcp) + len(payload))
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = socket.inet_aton("10.0.0.1")
    ip[16:20] = socket.inet_aton("10.0.0.2")
    return b"\x00" * 12 + b"\x08\x00" + bytes(ip) + bytes(tcp) + payload


def rtp(payload_type: int, sequence: int, timestamp: int, ssrc: int, audio: bytes) -> bytes:
    return struct.pack("!BBHII", 0x80, payload_type, sequence, timestamp, ssrc) + audio


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in frames:
            sec = int(timestamp)
            usec = int(round((timestamp - sec) * 1_000_000))
            output.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            output.write(frame)


def write_pcapng(path: Path, frames: list[tuple[float, bytes]]) -> None:
    def block(block_type: int, body: bytes) -> bytes:
        body += b"\x00" * ((-len(body)) % 4)
        length = 12 + len(body)
        return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)

    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    packets = []
    for timestamp, frame in frames:
        ticks = round(timestamp * 1_000_000)
        body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame
        packets.append(block(6, body))
    path.write_bytes(section + interface + b"".join(packets))


class ToolTests(unittest.TestCase):
    def test_invite_200_is_answered_and_unrelated_200_is_not(self):
        invite_ok = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP host\r\nCSeq: 42 INVITE\r\n\r\n"
        options_ok = b"SIP/2.0 200 OK\r\nCSeq: 9 OPTIONS\r\n\r\n"
        self.assertTrue(tool._contains_invite_200(invite_ok))
        self.assertFalse(tool._contains_invite_200(options_ok))

    def test_export_answered_g711_capture_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "20260903-10086-13800138000-abc.pcap"
            sip = b"SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
            frames = [(1.0, udp_frame(sip, 5060, 5060))]
            for index in range(3):
                audio = bytes([0xD5] * 160)
                frames.append((1.1 + index * 0.02, udp_frame(rtp(8, 100 + index, index * 160, 1234, audio), 10000, 20000)))
            write_pcap(capture, frames)
            output = root / "out"
            result = tool.process_file(capture, output, "all")
            self.assertTrue(result.answered)
            self.assertIsNotNone(result.wav)
            self.assertEqual(result.stream_count, 1)
            with wave.open(str(result.wav), "rb") as wav_file:
                self.assertEqual(wav_file.getframerate(), 8000)
                self.assertEqual(wav_file.getnchannels(), 1)
                self.assertEqual(wav_file.getnframes(), 480)
            report = tool.write_report(output, [result])
            with report.open(encoding="utf-8-sig", newline="") as source:
                rows = list(csv.reader(source))
            self.assertEqual(rows[1][1], "已接通")
            self.assertEqual(
                rows[0][-9:],
                ["检测语言", "语言置信度", "识别原文", "翻译目标语言", "翻译文本", "提示音分类", "ASR结果", "翻译结果", "结果"],
            )

    def test_two_rtp_directions_export_stereo_and_channel_wavs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "answered.pcap"
            sip = b"SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\n\r\n"
            frames = [(1.0, udp_frame(sip, 5060, 5060))]
            for index in range(3):
                frames.append((1.1 + index * 0.02, udp_frame(rtp(8, index, index * 160, 11, b"\xd5" * 160), 10000, 20000)))
                frames.append((1.11 + index * 0.02, udp_frame(
                    rtp(8, index, index * 160, 22, b"\x55" * 160),
                    20000,
                    10000,
                    src="10.0.0.2",
                    dst="10.0.0.1",
                )))
            write_pcap(capture, frames)

            results = tool.process_capture(capture, root / "out", "all", "separate")

            self.assertEqual([item.channel for item in results], ["左声道", "右声道"])
            self.assertTrue(all(item.wav.is_file() for item in results))
            self.assertTrue(all(item.quality is not None for item in results))
            self.assertTrue(all(not item.quality.suspected_stutter for item in results))
            with wave.open(str(root / "out" / "已接通" / "answered.wav"), "rb") as stereo:
                self.assertEqual(stereo.getnchannels(), 2)
            for item in results:
                with wave.open(str(item.wav), "rb") as mono:
                    self.assertEqual(mono.getnchannels(), 1)

    def test_asr_defaults_to_unanswered_wav(self):
        class Recognizer:
            def __init__(self):
                self.paths = []

            def transcribe(self, path):
                self.paths.append(path)
                return "您拨打的号码暂时无法接通"

        unanswered = tool.Result(Path("unanswered.pcap"), wav=Path("unanswered.wav"))
        answered = tool.Result(Path("answered.pcap"), answered=True, wav=Path("answered.wav"))
        no_audio = tool.Result(Path("no-audio.pcap"))
        recognizer = Recognizer()

        tool.transcribe_results([unanswered, answered, no_audio], recognizer)

        self.assertEqual(recognizer.paths, [Path("unanswered.wav")])
        self.assertEqual(unanswered.transcript, "您拨打的号码暂时无法接通")
        self.assertEqual(unanswered.asr_note, "识别成功")
        self.assertEqual(answered.asr_note, "")
        self.assertEqual(no_audio.asr_note, "无可识别录音")

    def test_asr_can_transcribe_answered_or_all_wav(self):
        class Recognizer:
            def __init__(self):
                self.paths = []

            def transcribe(self, path):
                self.paths.append(path)
                return path.stem

        unanswered = tool.Result(Path("unanswered.pcap"), wav=Path("unanswered.wav"))
        answered = tool.Result(Path("answered.pcap"), answered=True, wav=Path("answered.wav"))
        recognizer = Recognizer()

        tool.transcribe_results([unanswered, answered], recognizer, "answered")

        self.assertEqual(recognizer.paths, [Path("answered.wav")])
        self.assertEqual(answered.transcript, "answered")
        self.assertEqual(unanswered.transcript, "")

        recognizer = Recognizer()
        tool.transcribe_results([unanswered, answered], recognizer, "all")
        self.assertEqual(recognizer.paths, [Path("unanswered.wav"), Path("answered.wav")])

    def test_asr_status_parser_defaults_to_unanswered(self):
        parser = tool.build_parser()

        defaults = parser.parse_args(["capture.pcap"])
        answered = parser.parse_args(["capture.pcap", "--asr-status", "answered"])
        spanish = parser.parse_args(["capture.pcap", "--translate-language", "ES"])

        self.assertEqual(defaults.asr_status, "unanswered")
        self.assertEqual(defaults.asr_language, "auto")
        self.assertEqual(defaults.channel_mode, "separate")
        self.assertEqual(defaults.translate_language, "zh")
        self.assertFalse(defaults.no_translate)
        self.assertEqual(answered.asr_status, "answered")
        self.assertEqual(spanish.translate_language, "es")

    def test_foreign_asr_detects_language_and_translates_to_chinese(self):
        class Recognizer:
            def transcribe(self, _path):
                return tool.Recognition("El numero no esta disponible", "es", 0.985)

            def translate_to_english(self, _path, language):
                self.language = language
                return "The number is unavailable"

        class Translator:
            def translate(self, text):
                self.text = text
                return "该号码暂时无法接通"

        result = tool.Result(Path("spanish.wav"), direct_wav=True, wav=Path("spanish.wav"))
        recognizer = Recognizer()
        translator = Translator()

        tool.transcribe_results([result], recognizer, translator=translator, target_language="zh")

        self.assertEqual(result.detected_language, "es")
        self.assertEqual(result.language_probability, 0.985)
        self.assertEqual(recognizer.language, "es")
        self.assertEqual(translator.text, "The number is unavailable")
        self.assertEqual(result.translation_language, "zh")
        self.assertEqual(result.translated_text, "该号码暂时无法接通")
        self.assertEqual(result.translation_note, "翻译成功")

    def test_foreign_asr_preserves_spaces_between_segments(self):
        segments = [SimpleNamespace(text=" Hola"), SimpleNamespace(text=" mundo"), SimpleNamespace(text=".")]

        self.assertEqual(tool.join_segment_texts(segments), "Hola mundo.")

    def test_chinese_asr_does_not_call_translator(self):
        class Recognizer:
            def transcribe(self, _path):
                return tool.Recognition("您拨打的号码无法接通", "zh", 0.99)

        class Translator:
            def translate(self, _text):
                raise AssertionError("中文不应再次翻译")

        result = tool.Result(Path("chinese.wav"), direct_wav=True, wav=Path("chinese.wav"))

        tool.transcribe_results([result], Recognizer(), translator=Translator(), target_language="zh")

        self.assertEqual(result.translated_text, result.transcript)
        self.assertEqual(result.translation_note, "原文已是目标语言，无需翻译")

    def test_translation_target_can_be_changed(self):
        class Recognizer:
            def transcribe(self, _path):
                return tool.Recognition("The line is busy", "en", 0.99)

        class Translator:
            def translate(self, text):
                self.text = text
                return "La linea esta ocupada"

        result = tool.Result(Path("english.wav"), direct_wav=True, wav=Path("english.wav"))
        translator = Translator()

        tool.transcribe_results([result], Recognizer(), translator=translator, target_language="es")

        self.assertEqual(translator.text, "The line is busy")
        self.assertEqual(result.translation_language, "es")
        self.assertEqual(result.translated_text, "La linea esta ocupada")

    def test_direct_wav_is_transcribed_and_reported(self):
        class Recognizer:
            def __init__(self, _model, _model_dir, _language):
                pass

            def transcribe(self, path):
                self.path = path
                return tool.Recognition("这是指定 WAV 的识别内容", "zh", 0.97)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav_path = root / "call.wav"
            with wave.open(str(wav_path), "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(8000)
                wav_file.writeframes(b"\x00\x00" * 160)
            output = root / "out"

            with mock.patch.object(tool, "FasterWhisperRecognizer", Recognizer):
                exit_code = tool.main([str(wav_path), "-o", str(output), "--asr"])

            self.assertEqual(exit_code, 0)
            with (output / "导出报告.csv").open(encoding="utf-8-sig", newline="") as source:
                rows = list(csv.reader(source))
            report_row = dict(zip(rows[0], rows[1]))
            self.assertEqual(report_row["抓包文件"], str(wav_path))
            self.assertEqual(report_row["接通状态"], "直接WAV")
            self.assertEqual(report_row["声道"], "单声道")
            self.assertEqual(report_row["疑似卡顿"], "无法判断（无RTP）")
            self.assertEqual(report_row["检测语言"], "中文 (zh)")
            self.assertEqual(report_row["语言置信度"], "97.00%")
            self.assertEqual(report_row["识别原文"], "这是指定 WAV 的识别内容")
            self.assertTrue((output / "提示音分类汇总.csv").is_file())

    def test_direct_stereo_wav_is_split_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav_path = root / "stereo.wav"
            frames = b"".join(struct.pack("<hh", left, right) for left, right in [(100, -100), (200, -200)])
            with wave.open(str(wav_path), "wb") as wav_file:
                wav_file.setnchannels(2)
                wav_file.setsampwidth(2)
                wav_file.setframerate(8000)
                wav_file.writeframes(frames)

            results = tool.prepare_direct_wav(wav_path, root / "out", "separate")

            self.assertEqual([item.channel for item in results], ["左声道", "右声道"])
            with wave.open(str(results[0].wav), "rb") as left:
                self.assertEqual(left.readframes(2), struct.pack("<hh", 100, 200))
            with wave.open(str(results[1].wav), "rb") as right:
                self.assertEqual(right.readframes(2), struct.pack("<hh", -100, -200))

            mixed = tool.prepare_direct_wav(wav_path, root / "out", "mixed")
            self.assertEqual(len(mixed), 1)
            self.assertEqual(mixed[0].channel, "混合")
            self.assertEqual(mixed[0].wav, wav_path)

    def test_asr_failure_does_not_stop_other_results(self):
        class Recognizer:
            def transcribe(self, _path):
                raise RuntimeError("bad audio")

        result = tool.Result(Path("unanswered.pcap"), wav=Path("unanswered.wav"))

        tool.transcribe_results([result], Recognizer())

        self.assertEqual(result.asr_note, "识别失败：bad audio")

    def test_similar_transcripts_are_grouped_and_distinct_prompts_stay_separate(self):
        results = [
            tool.Result(Path("a.pcap"), transcript="您拨打的号码暂时无法接通，请稍后再拨。"),
            tool.Result(Path("b.pcap"), transcript="您拨打的号码暂时无法接通请稍后再拨"),
            tool.Result(Path("c.pcap"), transcript="您拨打的用户暂时无法接通，请稍后再拨"),
            tool.Result(Path("d.pcap"), transcript="您拨打的用户已关机"),
        ]

        groups = tool.classify_transcripts(results)

        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0].count, 3)
        self.assertEqual(results[0].prompt_category, "提示音-001")
        self.assertEqual(results[1].prompt_category, "提示音-001")
        self.assertEqual(results[2].prompt_category, "提示音-001")
        self.assertEqual(results[3].prompt_category, "提示音-002")

    def test_chinese_translation_is_used_for_classification(self):
        results = [
            tool.Result(Path("es.wav"), transcript="Numero ocupado", translated_text="线路忙，请稍后再拨"),
            tool.Result(Path("en.wav"), transcript="Line busy", translated_text="线路忙请稍后再拨"),
        ]

        groups = tool.classify_transcripts(results)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].count, 2)

    def test_transcript_normalization_ignores_punctuation_and_number_values(self):
        left = tool.normalize_transcript("号码 138-0013-8000 暂停服务！")
        right = tool.normalize_transcript("号码13900139000暂停服务")

        self.assertEqual(left, right)

    def test_rtp_quality_detects_continuous_packet_loss(self):
        packets = [
            tool.RtpPacket(1.00, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 1, 0, 7, b"\xd5" * 160),
            tool.RtpPacket(1.02, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 2, 160, 7, b"\xd5" * 160),
            tool.RtpPacket(1.08, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 5, 640, 7, b"\xd5" * 160),
        ]
        stream = tool.Stream(("10.0.0.1", 10000, "10.0.0.2", 20000, 7), 8, packets)

        quality = tool.analyze_stream_quality(stream)

        self.assertEqual(quality.received_packets, 3)
        self.assertEqual(quality.lost_packets, 2)
        self.assertEqual(quality.loss_events, 1)
        self.assertAlmostEqual(quality.longest_gap_ms, 40.0)
        self.assertTrue(quality.suspected_stutter)
        self.assertTrue(any("最长连续缺口" in reason for reason in quality.reasons))

    def test_rtp_quality_normal_stream_is_not_suspected(self):
        packets = [
            tool.RtpPacket(1.00 + index * 0.02, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, index, index * 160, 7, b"\xd5" * 160)
            for index in range(20)
        ]
        stream = tool.Stream(("10.0.0.1", 10000, "10.0.0.2", 20000, 7), 8, packets)

        quality = tool.analyze_stream_quality(stream)

        self.assertEqual(quality.lost_packets, 0)
        self.assertAlmostEqual(quality.jitter_ms, 0.0)
        self.assertFalse(quality.suspected_stutter)

    def test_rtp_quality_counts_reordered_and_duplicate_packets(self):
        packets = [
            tool.RtpPacket(1.00, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 1, 0, 7, b"\xd5" * 160),
            tool.RtpPacket(1.02, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 3, 320, 7, b"\xd5" * 160),
            tool.RtpPacket(1.04, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 2, 160, 7, b"\xd5" * 160),
            tool.RtpPacket(1.05, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 2, 160, 7, b"\xd5" * 160),
        ]
        stream = tool.Stream(("10.0.0.1", 10000, "10.0.0.2", 20000, 7), 8, packets)

        quality = tool.analyze_stream_quality(stream)

        self.assertEqual(quality.lost_packets, 0)
        self.assertEqual(quality.out_of_order_packets, 1)
        self.assertEqual(quality.duplicate_packets, 1)

    def test_sequence_gap_without_audio_timestamp_gap_is_not_loss(self):
        packets = [
            tool.RtpPacket(1.00, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 1, 0, 7, b"\xd5" * 160),
            tool.RtpPacket(1.02, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 3, 160, 7, b"\xd5" * 160),
            tool.RtpPacket(1.04, "10.0.0.1", "10.0.0.2", 10000, 20000, 8, 4, 320, 7, b"\xd5" * 160),
        ]
        stream = tool.Stream(("10.0.0.1", 10000, "10.0.0.2", 20000, 7), 8, packets)

        quality = tool.analyze_stream_quality(stream)

        self.assertEqual(quality.lost_packets, 0)
        self.assertFalse(quality.suspected_stutter)

    def test_report_contains_stutter_conclusion_and_evidence(self):
        quality = tool.RtpQuality(10, 2, 1, 2 / 12, 40.0, 5.0, 0, 0, True, ("丢包率 16.67%", "最长连续缺口 40.0ms"))
        result = tool.Result(Path("call.pcap"), channel="左声道", quality=quality)
        with tempfile.TemporaryDirectory() as directory:
            report = tool.write_report(Path(directory), [result])

            with report.open(encoding="utf-8-sig", newline="") as source:
                row = next(csv.DictReader(source))

        self.assertEqual(row["疑似卡顿"], "是")
        self.assertEqual(row["推测丢包数"], "2")
        self.assertIn("最长连续缺口", row["卡顿依据"])

    def test_main_reports_stutter_without_asr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "loss.pcap"
            frames = []
            for sequence, timestamp, capture_time in [(1, 0, 1.00), (2, 160, 1.02), (5, 640, 1.08)]:
                frames.append((capture_time, udp_frame(
                    rtp(8, sequence, timestamp, 7, b"\xd5" * 160),
                    10000,
                    20000,
                )))
            write_pcap(capture, frames)
            output = root / "out"

            exit_code = tool.main([str(capture), "-o", str(output), "--channel-mode", "mixed"])

            self.assertEqual(exit_code, 0)
            with (output / "导出报告.csv").open(encoding="utf-8-sig", newline="") as source:
                row = next(csv.DictReader(source))
            self.assertEqual(row["疑似卡顿"], "是")
            self.assertEqual(row["推测丢包数"], "2")
            self.assertEqual(row["ASR结果"], "")

    def test_category_report_contains_representative_and_count(self):
        with tempfile.TemporaryDirectory() as directory:
            results = [
                tool.Result(Path("a.pcap"), transcript="线路忙，请稍后再拨"),
                tool.Result(Path("b.pcap"), transcript="线路忙请稍后再拨"),
            ]
            groups = tool.classify_transcripts(results)

            report = tool.write_category_report(Path(directory), groups)

            with report.open(encoding="utf-8-sig", newline="") as source:
                rows = list(csv.reader(source))
            self.assertEqual(rows[0], ["提示音分类", "数量", "代表内容", "识别文本变体"])
            self.assertEqual(rows[1][0:2], ["提示音-001", "2"])

    def test_unanswered_filter_skips_answered_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "answered.pcap"
            sip = b"SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\n\r\n"
            frames = [(1.0, udp_frame(sip, 5060, 5060))]
            for index in range(2):
                frames.append((1.1 + index * 0.02, udp_frame(rtp(0, index, index * 160, 99, b"\xff" * 160), 10000, 20000)))
            write_pcap(capture, frames)
            result = tool.process_file(capture, root / "out", "unanswered")
            self.assertTrue(result.answered)
            self.assertIsNone(result.wav)
            self.assertEqual(result.note, "已按接通状态跳过")

    def test_no_media_is_reported_without_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "unanswered.pcap"
            write_pcap(capture, [(1.0, udp_frame(b"SIP/2.0 486 Busy Here\r\nCSeq: 1 INVITE\r\n\r\n", 5060, 5060))])
            result = tool.process_file(capture, root / "out", "unanswered")
            self.assertFalse(result.answered)
            self.assertIsNone(result.wav)
            self.assertIn("未发现", result.note)

    def test_pcapng_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "early-media.pcapng"
            frames = []
            for index in range(2):
                frames.append((2.0 + index * 0.02, udp_frame(rtp(0, index, index * 160, 7, b"\xff" * 160), 12000, 22000)))
            write_pcapng(path, frames)
            answered, streams, _packet_count, _payload_types = tool.inspect_capture(path)
            self.assertFalse(answered)
            self.assertEqual(len(streams), 1)

    def test_truncated_pcap_tail_keeps_complete_rtp_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "truncated.pcap"
            frames = [
                (1.0 + index * 0.02, udp_frame(rtp(8, index, index * 160, 1234, b"\xd5" * 160), 10000, 20000))
                for index in range(3)
            ]
            write_pcap(path, frames)
            with path.open("ab") as output:
                output.write(struct.pack("<IIII", 2, 0, 200, 200) + b"incomplete")

            result = tool.process_file(path, root / "out", "all")

            self.assertIsNotNone(result.wav)
            self.assertEqual(result.packet_count, 3)
            self.assertEqual(result.note, "导出成功（已忽略尾部截断数据）")

    def test_truncated_pcapng_tail_keeps_complete_rtp_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "truncated.pcapng"
            frames = [
                (1.0 + index * 0.02, udp_frame(rtp(0, index, index * 160, 7, b"\xff" * 160), 12000, 22000))
                for index in range(3)
            ]
            write_pcapng(path, frames)
            with path.open("ab") as output:
                output.write(struct.pack("<II", 6, 100) + b"incomplete")

            result = tool.process_file(path, root / "out", "all")

            self.assertIsNotNone(result.wav)
            self.assertEqual(result.packet_count, 3)
            self.assertEqual(result.note, "导出成功（已忽略尾部截断数据）")

    def test_truncated_global_header_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "broken.pcap"
            path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)

            result = tool.process_file(path, root / "out", "all")

            self.assertEqual(result.note, "处理失败：抓包文件被截断")

    def test_segmented_tcp_invite_200_is_reassembled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tcp-signaling.pcap"
            first = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP host\r\nCS"
            second = b"eq: 77 INVITE\r\nContent-Length: 0\r\n\r\n"
            write_pcap(path, [(1.0, tcp_frame(first, 1000)), (1.01, tcp_frame(second, 1000 + len(first)))])
            answered, _streams, _packet_count, _payload_types = tool.inspect_capture(path)
            self.assertTrue(answered)


if __name__ == "__main__":
    unittest.main()
