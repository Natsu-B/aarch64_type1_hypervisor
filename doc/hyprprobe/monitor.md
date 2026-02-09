# HyprProbe Monitor Commands (gdb branch)

このドキュメントは、HyprProbe の **GDB `monitor` コマンド**（GDB Remote Serial Protocol の `qRcmd` 経由でターゲットに渡る “文字列コマンド”）の仕様をまとめたものです。

---

## 1. 使い方（GDB 側）

GDB から以下の形で実行します。

- `monitor help`
- `monitor hp ...`

**注意:** ターゲット側に渡るコマンド文字列は、`monitor` の後ろの文字列です。  
例: `monitor hp memfault?` はターゲットへ `"hp memfault?"` が渡ります。

---

## 2. 文字列パース規則（共通）

### 2.1 トークン分割
- ASCII whitespace（`split_ascii_whitespace()`）で分割されます。 

### 2.2 数値（Bootloader 側 `hp memfault ignore ...` 等）
- 10進、または `0x`/`0X` プレフィクス付き 16進を受理します。 

### 2.3 数値（Semihost 側）
- `read <n>` の `<n>` は `usize`（10進 or 0x16進）。 
- `reply <result> <errno>` は `result: i64`、`errno: i32`（10進 or 0x16進、`result` は `-` も可）。 

---

## 3. 出力規則（重要）

### 3.1 末尾改行（`\n`）
- **Semihost 系（`hp semihost*`）は原則 `\n` を付けます。**  
  例: `hp semihost?` は `no\n` を返します。 
- **Bootloader 側の多くの応答（`hp memfault*`, `hp vbar*`, `hp gdb*` 等）は末尾改行なし**の形式が中心です（`help` は複数行 `\n` 付き）。 

### 3.2 エラー表現
- Bootloader 側: `error=<reason>`（改行なし） 
- Semihost 側: `error <msg>\n`（改行あり） 

### 3.3 応答の切り詰め
- Bootloader 側は内部バッファに収まる範囲で出力され、状況により切り詰めが起こり得ます。
- `help` や `vbar bt` の一部では、バッファ不足時に `...TRUNCATED` を末尾に強制挿入します。 

---

## 4. コマンド一覧（`monitor hp help` の表示に準拠）

`monitor hp help` は次の一覧を返します。 

- `monitor help`
- `monitor hp help`
- `monitor hp memfault?`
- `monitor hp memfault last|clear`
- `monitor hp memfault policy get|set <off|trap|autoskip>`
- `monitor hp memfault ignore add <addr> <len>`
- `monitor hp memfault ignore add_last <len>`
- `monitor hp memfault ignore del <addr> <len>`
- `monitor hp memfault ignore list`
- `monitor hp semihost?`
- `monitor hp semihost info`
- `monitor hp semihost read <n>`
- `monitor hp semihost reply <result> <errno>`
- `monitor hp semihost alloc_handle`
- `monitor hp semihost reset`
- `monitor hp gdb stop-counters`
- `monitor hp vbar <status|last|clear|check|bt?|bt>`

以下、各コマンドの仕様です。

---

## 5. `help` / `hp help`

### 5.1 `monitor help`
- 入力: `help`
- 成功: コマンド一覧（複数行、各行末尾に `\n`）。 
- 余分な引数がある場合: `error=extra_args` 

### 5.2 `monitor hp help`
- 入力: `hp help`
- 成功/失敗は `monitor help` と同様。 

---

## 6. `hp gdb stop-counters`

### 6.1 目的
GDB 側への stop reply（`Txx...` など）の送信に関する統計を表示します。

### 6.2 仕様
- 入力: `hp gdb stop-counters`
- 成功:  
  `queued=<u32> overflow=<u32> sent=<u32>`（改行なし） 
- エラー:
  - 引数過多: `error=extra_args`
  - サブコマンド不正: `error=bad_args` 

---

## 7. `hp memfault*`（MMIO 以外 / 許可外アクセス検知の状態確認）

### 7.1 `monitor hp memfault?`
- 入力: `hp memfault?`
- 出力: **pending の有無（yes/no）と、必要に応じて詳細**（改行なしが基本）。
  - 詳細は `write_memfault_info` のフォーマットに準拠します。 

### 7.2 `monitor hp memfault last`
- 入力: `hp memfault last`
- 出力:
  - 最後の memfault が無い場合: `none`
  - ある場合: `write_memfault_info` 相当の情報（改行なし） 

### 7.3 `monitor hp memfault clear`
- 入力: `hp memfault clear`
- 効果: memfault の pending 状態をクリアします（次の `memfault?` の判定に影響）。
- 出力: `ok`（改行なしが基本）

### 7.4 `monitor hp memfault policy get`
- 入力: `hp memfault policy get`
- 出力: `policy=<off|warn|trap|autoskip>`（改行なしが基本）
  - 実装上は `warn` も定義されています（help 表示には出ません）。 

### 7.5 `monitor hp memfault policy set <policy>`
- 入力: `hp memfault policy set <off|trap|autoskip>`（実装上は `warn` もパース対象） 
- 出力: `ok policy=<...>`（改行なしが基本）
- エラー:
  - policy 不正: `error=bad_policy`
  - 引数不足/過多: `error=bad_args` / `error=extra_args`

### 7.6 `monitor hp memfault ignore add <addr> <len>`
- 入力: `hp memfault ignore add <addr> <len>`
- 効果: 監視対象から除外する範囲（base/len）を追加。
- エラー理由（Bootloader 内部の戻り値に対応）:
  - `bad_len`（len=0 等）
  - `bad_range`（base+len がオーバーフロー等）
  - `full`（登録スロット枯渇）
  - 既存と同一範囲は no-op で成功扱い 
- 出力: `ok ...`（改行なしが基本）

### 7.7 `monitor hp memfault ignore add_last <len>`
- 入力: `hp memfault ignore add_last <len>`
- 効果: 最後の memfault の `addr` を base として ignore 範囲を追加。 
- エラー: `no_last`（last が無い）
- 出力: `ok ...`（改行なしが基本）

### 7.8 `monitor hp memfault ignore del <addr> <len>`
- 入力: `hp memfault ignore del <addr> <len>`
- エラー: `not_found`
- 出力: `ok ...`（改行なしが基本） 

### 7.9 `monitor hp memfault ignore list`
- 入力: `hp memfault ignore list`
- 出力:  
  `count=<n> entries=0x<base>+0x<len>,0x<base>+0x<len>,...`（改行なし） 

### 7.10 memfault 詳細フォーマット（`write_memfault_info`）
`addr=0x... kind=<read|write|access> access=<r|w> size=<n> esr=0x... elr=0x... ipa=<0x...|none> far=0x... reg=<n|none> class=<allowlisted|invalid>` 

---

## 8. `hp semihost*`（ゲスト semihosting のホスト処理支援）

Semihost monitor は **Semihost 実装側が優先的に処理**します（`hp semihost?` / `hp semihost ...` を先に解釈）。 

### 8.1 `monitor hp semihost?`
- 入力: `hp semihost?`
- 成功:
  - pending が無い: `no\n`
  - pending がある: `yes op=0x<op> args=0x<args_ptr> insn=0x<insn_addr>\n` 
- エラー: `error extra_args\n`（引数過多） 

### 8.2 `monitor hp semihost info`
- 入力: `hp semihost info`
- 成功（末尾 `\n` あり）:
  - `Write0`: `op=write0 str=0x<addr>\n`
  - `Open`: `path=0x<addr> len=<n> mode=<mode>\n`
  - `Write`: `handle=<h> buf=0x<addr> len=<n>\n`
  - `Close`: `handle=<h>\n` 
- エラー（例）:
  - `error no_pending\n`
  - `error unsupported_op\n`
  - `error decode_failed\n` 

### 8.3 `monitor hp semihost read <n>`
- 入力: `hp semihost read <n>`
- 目的: semihost リクエストが参照するメモリ（文字列/バッファ等）を最大 `<n>` バイト読み、hex で返す。
- 成功:
  - `hex:<hexbytes>\n`
  - まだ続きがある場合: `hex:<hexbytes> truncated=1\n`
  - 読み終わり後（2回目以降等）: `hex:\n` 
- エラー例:
  - `error bad_len\n`（len のパース失敗）
  - `error too_large\n`（上限超過）
  - `error mem_read\n`（メモリ読取り失敗）
  - `error bad_op\n`（Close など read 不適） 

### 8.4 `monitor hp semihost reply <result> <errno>`
- 入力: `hp semihost reply <result> <errno>`
- 目的: pending の semihost リクエストへ完了値を注入する。
- 成功: `ok\n`
- エラー例:
  - `error no_pending\n`
  - `error already_completed\n`
  - `error bad_args\n`（数値パース失敗/引数不足） 

### 8.5 `monitor hp semihost alloc_handle`
- 入力: `hp semihost alloc_handle`
- 出力: `handle=<u32>\n` 

### 8.6 `monitor hp semihost reset`
- 入力: `hp semihost reset`
- 効果: semihost state をクリア（pending/completion/read_offset 等）。
- 出力: `ok\n` 

---

## 9. `hp vbar*`（VBAR_EL1 監視関連）

### 9.1 `monitor hp vbar status`
- 出力（改行なし）:  
  `enabled=<0|1> mode=<...> current_vbar_va=0x... current_vbar_ipa=0x... live_vbar=0x... pending_repatch=<0|1> step_depth=<n> change_seq=<n> change_reason=<...>`  
  追加で:
  - live と snapshot が不一致なら `warning=vbar_changed ...`
  - last_error があれば `error=<reason> err_vbar=0x...` 

### 9.2 `monitor hp vbar last`
- 出力:
  - ヒット無し: `none`
  - あり: `slot=... offset=0x... brk_pc=0x... esr_el2=0x... elr_el2=0x... origin_pc=0x... origin_spsr_el1=0x... origin_mode=... origin_pre_sp=... origin_sp_el0=0x... origin_sp_el1=0x... origin_esr_el1=0x... origin_far_el1=0x... nested=<0|1>` 

### 9.3 `monitor hp vbar clear`
- 効果: last hit をクリア。
- 出力: `ok`（改行なしが基本）

### 9.4 `monitor hp vbar check`
- 目的: VBAR 監視状態の一貫性チェック（実装側チェック関数）。
- 出力: `ok` または `error=...`（改行なしが基本）

### 9.5 `monitor hp vbar bt?`（バックトレース・メタ情報）
- 出力:
  - 無し: `none`
  - あり: `seq=<n> depth=<n> nested=<0|1> version=1` 

### 9.6 `monitor hp vbar bt`（バックトレース・ダンプ）
- 出力:
  - 無し: `none`
  - あり:
    - 先頭: `version=1 seq=<n> depth=<n> stride=56 fields=pc,sp,fp,lr,spsr,esr,far data=`
    - 続けて `depth` フレーム分の `pc/sp/fp/lr/spsr/esr/far`（各 u64、little-endian）を **hex で連結** 
  - バッファ不足時: 末尾に `...TRUNCATED` 
