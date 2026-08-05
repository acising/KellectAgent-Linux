#!/usr/bin/env bash
# =============================================================================
# KellectAgent-Linux 手动补测 —— 覆盖自动套件(test_kellect.sh)测不到的
# 3 个核心判据:
#   (a) console 模式逐 loader Ctrl-C 干净退出 + 循环后清理路径不崩溃
#   (b) -o 模式 DCStart/DCEnd 快照计数(对标 Windows DC_START/DC_END)
#   (c) #8 用户态过滤 --comm
#
# 用法:
#   cd ~/kellect-linux
#   sudo bash test/manual_verify.sh
#   sudo KELLECT_BIN=./release/kellect bash test/manual_verify.sh   # 指定二进制
#
# 前提:已在信创主机 make kellect 成功,release/kellect 存在。
# 判据来源:开发交接文档-20260805.md §4.4 / §4.5
#
# 若从 Windows 拷来报 "bad interpreter: \r" 或行尾 ^M,先:
#   sed -i 's/\r$//' test/manual_verify.sh
# =============================================================================
set -u

BIN="${KELLECT_BIN:-./release/kellect}"
[ -x "$BIN" ] || { echo "❌ 找不到可执行 $BIN(先 make kellect)"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "❌ 需 root(eBPF)。请用: sudo bash $0"; exit 1; }

TMP="$(mktemp -d -t kellect-manual.XXXXXX)"
PASS=0; FAIL=0
ok(){ printf '  ✅ PASS: %s\n' "$*"; PASS=$((PASS+1)); }
no(){ printf '  ❌ FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }
log(){ printf '\n[%s] ===== %s =====\n' "$(date +%H:%M:%S)" "$*"; }

# ---------------------------------------------------------------------------
# (a) console 模式逐 loader:Ctrl-C 干净退出 + 循环后清理路径
#     重点激活 all/conf/file/user 从未跑过的 ring_buffer__free + *_bpf__destroy。
#     console 模式 output_X==NULL,fclose 被守卫跳过 —— 这里专测清理路径。
# ---------------------------------------------------------------------------
log "(a) console 模式 Ctrl-C 干净退出 + 清理路径"
for EV in all process file network user conf; do
  printf '\n  --- %s ---\n' "$EV"
  "$BIN" -e "$EV" > "$TMP/con_$EV.log" 2>&1 &
  KPID=$!
  sleep 3
  kill -INT "$KPID" 2>/dev/null
  wait "$KPID"; RC=$?
  printf '  exit=%s\n' "$RC"
  case $RC in
    0)   ok "$EV 干净退出(exit=0)";;
    130) no "$EV exit=130 —— SIGINT 默认终止,handle_signal 未注册/未生效";;
    139) no "$EV exit=139 —— 段崩溃,循环后清理路径有 bug,查 $TMP/con_$EV.log";;
    *)   no "$EV exit=$RC(非 0,异常)";;
  esac
done

# ---------------------------------------------------------------------------
# (b) -o 模式 DCStart/DCEnd 快照(all/process/conf 三个有 #5 的 loader)
#     file/user/network 无 #5 快照,跳过(预期 DCStart=0/DCEnd=0,只看 (a) exit=0)。
# ---------------------------------------------------------------------------
log "(b) -o 模式 DCStart/DCEnd 快照(all/process/conf)"
NPROC=$(ps -e --no-headers | wc -l)
printf '  参考: ps -e 进程数(含内核线程)≈ %s\n' "$NPROC"
echo "  注: snapshot 跳过内核线程/无 exe 进程,DCStart 略小于此;只判 >0"
for EV in all process conf; do
  printf '\n  --- %s ---\n' "$EV"
  "$BIN" -e "$EV" -f json -o "$TMP/snap_$EV.json" > "$TMP/snap_$EV.log" 2>&1 &
  KPID=$!
  sleep 4
  kill -INT "$KPID" 2>/dev/null
  wait "$KPID"; RC=$?
  DS=$(grep -c '"EventName":"DCStart"' "$TMP/snap_$EV.json" 2>/dev/null)
  DE=$(grep -c '"EventName":"DCEnd"'   "$TMP/snap_$EV.json" 2>/dev/null)
  printf '  exit=%s  DCStart=%s  DCEnd=%s\n' "$RC" "${DS:-0}" "${DE:-0}"
  [ "$RC" -eq 0 ] && ok "$EV exit=0" || no "$EV exit=$RC"
  [ "${DS:-0}" -gt 0 ] && ok "$EV DCStart>0" || no "$EV DCStart=0(快照未生成)"
  [ "${DE:-0}" -gt 0 ] && ok "$EV DCEnd>0(循环后重定位成功)" || no "$EV DCEnd=0(DCEnd 仍在死分支)"
done

# ---------------------------------------------------------------------------
# (c) #8 用户态过滤 --comm bash
#     snapshot 全表绕过过滤(已知,见交接文档 §5);本项只看运行时事件。
# ---------------------------------------------------------------------------
log "(c) #8 用户态过滤 --comm bash"
echo "  snapshot 全表绕过过滤(已知);本项只看运行时事件(FORK/EXEC/EXIT)"
printf '\n  --- process --comm bash ---\n'
"$BIN" -e process --comm bash -f json -o "$TMP/f1.json" > "$TMP/f1.log" 2>&1 &
KPID=$!
sleep 1
bash -c 'echo hi >/dev/null; ls /tmp >/dev/null'   # 触发 bash 子进程 fork/exec
sleep 1
kill -INT "$KPID" 2>/dev/null
wait "$KPID"; RC=$?
printf '  exit=%s\n' "$RC"
# 运行时事件 = 排除 DCStart/DCEnd 快照行
RT=$(grep -v '"EventName":"DCStart"' "$TMP/f1.json" 2>/dev/null \
    | grep -v '"EventName":"DCEnd"' \
    | grep -o '"ProcessName":"[^"]*"' | sort -u)
DCNT=$(grep -c '"EventName":"DCStart"' "$TMP/f1.json" 2>/dev/null)
printf '  DCStart 快照行=%s(含全表,绕过过滤 —— 预期)\n' "${DCNT:-0}"
if [ -z "$RT" ]; then
  echo '  运行时事件 ProcessName: (空)'
  no "未捕获运行时 bash 事件(延长 sleep 或换触发动作重跑)"
else
  echo '  运行时事件 ProcessName 唯一值:'
  printf '%s\n' "$RT" | sed 's/^/    /'
  RTC=$(printf '%s\n' "$RT" | grep -c .)
  if printf '%s' "$RT" | grep -q '"ProcessName":"bash"'; then
    ok "--comm bash 过滤生效(运行时事件含 bash)"
    [ "$RTC" -gt 1 ] && printf '  ℹ 另有 %s 个 comm,可能是 exec 后程序名,人工确认是否该被过滤\n' "$((RTC-1))"
  else
    no "运行时事件无 bash(过滤异常或未触发)"
  fi
fi

# ---------------------------------------------------------------------------
log "汇总"
printf '  PASS=%s  FAIL=%s\n' "$PASS" "$FAIL"
printf '  原始输出/JSON 在: %s\n' "$TMP"
if [ "$FAIL" -eq 0 ]; then
  echo '  🎉 全部通过 → 可闭合 #5,推进 Phase 1 #6-A(TCP 完整性)'
else
  echo '  ⚠️ 有 FAIL → 先定位再推进:'
  echo '     段崩溃 → 看 $TMP/con_*.log,把崩溃行贴回 Windows 端'
  echo '     DCEnd=0 → 循环后重定位未生效,查 process.c:1236 / all.c:7776 / conf.c:7878'
  echo '     过滤异常 → 查 filter.h 在 handle_event 入口的早退逻辑'
fi
# =============================================================================
