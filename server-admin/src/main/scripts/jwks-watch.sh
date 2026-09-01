#!/usr/bin/env bash
# jwks-watch.sh -- watch test.cilogon.org JWKS for divergent or changing key sets.
#
# The endpoint round-robins across backends serving DIFFERENT key sets, so a
# single sample per tick would flip on every poll and tell you nothing. Each tick
# therefore fires a small burst and records the SET of distinct key sets seen.
#
# A line is printed only when something meaningful happens:
#   - a key set never seen before appears        (new instance / rotation)
#   - the set of concurrently-served key sets changes (divergence starts/ends)
#   - requests start or stop failing
#   - periodic heartbeat, so silence is never ambiguous
#
# Every tick is appended to timeline.csv regardless, so you get a full timeline
# for the bug report even though stdout stays quiet.
#
# Usage:   bash jwks-watch.sh
#          INTERVAL=15 BURST=12 bash jwks-watch.sh
#          nohup bash jwks-watch.sh > ~/jwks-watch/log.txt 2>&1 &
# Stop:    Ctrl-C, or kill the background pid.

set -uo pipefail

URL="${URL:-https://dev.cilogon.org/oauth2/certs}"
INTERVAL="${INTERVAL:-30}"        # seconds between ticks
BURST="${BURST:-8}"               # requests per tick
HEARTBEAT="${HEARTBEAT:-3600}"    # max seconds of silence before an "alive" line
OUTDIR="${OUTDIR:-$HOME/jwks-watch}"

mkdir -p "$OUTDIR/evidence" || exit 1
CSV="$OUTDIR/timeline.csv"
[[ -f "$CSV" ]] || echo "utc,label,kids,seen_in_burst,burst_size,errors" >> "$CSV"

command -v jq >/dev/null || { echo "FATAL: jq not found"; exit 1; }

declare -A LABEL_OF        # kid-set string -> short label
declare -A FIRST_SEEN
LABELS=(A B C D E F G H I J K L M N O P Q R S T U V W X Y Z)
label_idx=0

prev_state=""
prev_errors=0
last_output=$(date +%s)

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
emit() { echo "[$(ts)] $*"; last_output=$(date +%s); }

emit "watching $URL  (burst=$BURST every ${INTERVAL}s)  evidence -> $OUTDIR"

while :; do
  declare -A count_of=()
  errors=0
  tmp=$(mktemp)

  for ((i = 0; i < BURST; i++)); do
    if ! curl -sS --no-keepalive --max-time 15 -o "$tmp" "$URL" 2>/dev/null; then
      errors=$((errors + 1)); continue
    fi
    kids=$(jq -r 'try ([.keys[].kid] | sort | join(",")) // empty' "$tmp" 2>/dev/null)
    if [[ -z "$kids" ]]; then
      errors=$((errors + 1)); continue
    fi

    # First time we have ever seen this key set: label it and keep the body.
    if [[ -z "${LABEL_OF[$kids]:-}" ]]; then
      lbl="${LABELS[$label_idx]:-Z$label_idx}"
      label_idx=$((label_idx + 1))
      LABEL_OF[$kids]="$lbl"
      FIRST_SEEN[$kids]=$(ts)
      cp "$tmp" "$OUTDIR/evidence/jwks-$lbl.json"
      emit "NEW KEY SET $lbl -> $kids"
      emit "    full JWKS saved to $OUTDIR/evidence/jwks-$lbl.json"
    fi

    l="${LABEL_OF[$kids]}"
    count_of[$l]=$(( ${count_of[$l]:-0} + 1 ))
  done
  rm -f "$tmp"

  # State = which key sets were served concurrently this tick, e.g. "A+B".
  state=$(printf '%s\n' "${!count_of[@]}" | sort | paste -sd+ -)
  [[ -z "$state" ]] && state="(none)"

  # Human-readable distribution, e.g. "A=5 B=3"
  dist=""
  for l in $(printf '%s\n' "${!count_of[@]}" | sort); do
    dist+="$l=${count_of[$l]} "
  done

  if [[ "$state" != "$prev_state" ]]; then
    if [[ -z "$prev_state" ]]; then
      emit "baseline: serving $state   [$dist of $BURST]"
      if [[ "$state" == *+* ]]; then
        emit "    DIVERGENT -- more than one key set served concurrently"
      fi
    else
      emit "STATE CHANGE: $prev_state -> $state   [$dist of $BURST]"
      if [[ "$state" == *+* ]]; then
        emit "    DIVERGENT -- more than one key set served concurrently"
      else
        emit "    now consistent on $state"
      fi
    fi
    prev_state="$state"
  fi

  if (( errors > 0 && prev_errors == 0 )); then
    emit "ERRORS: $errors/$BURST requests failed"
  elif (( errors == 0 && prev_errors > 0 )); then
    emit "errors cleared"
  fi
  prev_errors=$errors

  # Timeline row per key set seen this tick.
  for kids in "${!LABEL_OF[@]}"; do
    l="${LABEL_OF[$kids]}"
    c="${count_of[$l]:-0}"
    (( c == 0 )) && continue
    echo "$(ts),$l,\"$kids\",$c,$BURST,$errors" >> "$CSV"
  done

  now=$(date +%s)
  if (( now - last_output >= HEARTBEAT )); then
    emit "still watching -- steady on $state [$dist of $BURST]"
  fi

  sleep "$INTERVAL"
done
