#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Proving Session — MCP server (stdio), 22 tools (§6).

"""Eclipse Proving Session — governed bench access for agents.

Spec: eclipse-proving-spec-20261025.md §6. The surface is exactly
22 tools: 16 Session (§6.1) + 3 Pin (§7.2) + 3 Gate (§8.2).
Deliberately ABSENT (§6.3/§6.4, enumeration-proven in tests):
fuse programming, PMIC/voltage config, boot-mode strap set, raw
Tcl/XSDB/shell escape hatches, wildcard board ops, admin verbs
(arm/freeze/revoke are owner admin-CLI acts, §6.2 — not tools).

Every call returns {ok, data | refusal, receipt_id}; every call —
success, refusal, or failure — appends a receipt (§11.2). Denied
parameter names (§6.4) refuse at this boundary, receipted, mapped
to their permanent codes where one exists. Target/evidence class
is honest everywhere: P0 targets are fixture + emulator; verdict
ceiling is CERTIFIED(simulator) (§13).

Transport: MCP over stdio (newline-delimited JSON-RPC 2.0),
stdlib only. Fixtures: $ECLIPSE_PROVING_FIXTURES or ./fixtures.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import bridge as bridge_mod  # noqa: E402
import proving_engine as engine  # noqa: E402
from proving_engine import Bridge, Refusal  # noqa: E402

BRIDGE = Bridge()

def _S(desc):
    return {"type": "string", "description": desc}


def _I(desc):
    return {"type": "integer", "description": desc}


def _REF(desc):
    return {"type": ["string", "object"], "description": desc}


def _ANN(read_only, idempotent, destructive=False):
    return {"readOnlyHint": read_only, "destructiveHint": destructive,
            "idempotentHint": idempotent, "openWorldHint": False}


def _ENV(data_props, data_required=None):
    """Output schema for the Proving envelope: every call returns
    {ok, data | refusal, receipt_id}; data carries the tool payload."""
    data = {"type": "object", "properties": data_props}
    if data_required:
        data["required"] = data_required
    return {"type": "object",
            "properties": {
                "ok": {"type": "boolean",
                       "description": "True when data carries the result; false when refusal carries a named refusal."},
                "data": data,
                "refusal": {"type": "object",
                            "description": "Present when ok is false: refusal_code, detail and op_id.",
                            "properties": {
                                "refusal_code": {"type": "string"},
                                "detail": {"type": "string"},
                                "op_id": {"type": "string"}}},
                "receipt_id": {"type": "string",
                               "description": "Id of the hash-chained receipt appended for this call."}},
            "required": ["ok", "receipt_id"]}

# tool -> (description, properties, required). Session tools take
# session_id (§6 conventions); bench_discover/session_open do not.
TOOLS = {
    "bench_discover": (
        "List the bench boards one mandate may see: board_id, "
        "board_rev, target_class, current state, strap_state, device "
        "part and the tiers the mandate grants on each board. Use "
        "before session_open to choose a board; boards the mandate "
        "does not name are never enumerated. The mandate's Herald "
        "signature is verified and revocation is checked even for "
        "discovery — an unsigned mandate refuses "
        "MANDATE_SIGNATURE_INVALID and a revoked one refuses "
        "MANDATE_REVOKED. Read-only apart from the receipt every "
        "call appends: no lease is taken and no board is touched. "
        "Local stdio server, targets in this build are fixture and "
        "emulator boards only, no rate limits. Every call returns "
        "the envelope {ok, data | refusal, receipt_id}. Returns "
        "data {boards, mandate_id}.",
        {"mandate_ref": _REF("Mandate to discover under: a mandate_id string known to the bridge, or the mandate object itself. The Herald signature is verified either way.")},
        ["mandate_ref"],
        _ENV({"boards": {"type": "array", "description": "One entry per mandate-named board: board_id, board_rev, target_class, state, strap_state, device_part, granted_tiers."},
              "mandate_id": {"type": "string", "description": "The mandate id discovery ran under."}},
             ["boards", "mandate_id"]),
        _ANN(True, True)),
    "session_open": (
        "Open a governed bench session on exactly one board under a "
        "Herald-signed mandate and take that board's exclusive "
        "lease. Use after bench_discover; every other session tool "
        "needs the returned session_id. Verification runs in order: "
        "the mandate's Herald signature, the agent identity is a "
        "known Herald card, the mandate is not revoked, the current "
        "time is inside its session bounds, the named board is in "
        "the mandate with at least one granted tier, the board's "
        "registry class matches its adapter's declared class, the "
        "mandate's session cap is not reached, and the board lease "
        "is free. Wildcard or empty board names refuse "
        "BOARD_WILDCARD_REFUSED; a held board refuses LEASE_HELD. "
        "Mutating: creates the session and lease in bridge memory. "
        "There is no admin verb on this surface — arming, freezing "
        "and revocation are owner acts outside the tool set, and "
        "parameters naming fuse, voltage/PMIC, strap setting or "
        "raw Tcl/shell access refuse at the boundary with named "
        "permanent codes, receipted. Returns data {session_id, "
        "granted_tiers, lease_expires_at, target_class}.",
        {"mandate": _REF("Herald-signed mandate: a mandate_id string known to the bridge, or the mandate object itself. Signature, identity, revocation and time bounds are all verified at open."),
         "board_id": _S("Exactly one board_id named in the mandate, as listed by bench_discover. Wildcards and empty names refuse BOARD_WILDCARD_REFUSED.")},
        ["mandate", "board_id"],
        _ENV({"session_id": {"type": "string", "description": "New session id; required by every other session tool."},
              "granted_tiers": {"type": "array", "description": "Tiers the mandate grants on this board, drawn from T0, T1, T2, T3."},
              "lease_expires_at": {"type": "string", "description": "ISO-8601 time the board lease expires."},
              "target_class": {"type": "string", "description": "The adapter-declared target class for this board (fixture or emulator in this build)."}},
             ["session_id", "granted_tiers", "lease_expires_at"]),
        _ANN(False, False)),
    "session_status": (
        "Read one open session's status snapshot: session state, "
        "board state, granted tiers, whether a live owner arm "
        "exists for T3, any active write window, receipt count, "
        "pack status, lease state and target class (tier T0). Use "
        "to check where a session stands before further operations; "
        "use bench_discover to find boards before a session "
        "exists. Read-only apart from the receipt every call "
        "appends. An unknown session_id refuses NO_MANDATE. "
        "Returns data {state, board_state, granted_tiers, "
        "t3_arm_state, write_window, receipt_count, pack_status, "
        "lease_state, target_class}.",
        {"session_id": _S("Session id returned by session_open.")},
        ["session_id"],
        _ENV({"state": {"type": "string", "description": "Session lifecycle state, e.g. OPEN, CONNECTED, ACTIVE, FROZEN, SEALED."},
              "board_state": {"type": "string", "description": "Board state as held by the bridge, e.g. LEASED, CONNECTED, ATTESTED, UNKNOWN, IDLE."},
              "granted_tiers": {"type": "array", "description": "Tiers granted to this session on its board."},
              "t3_arm_state": {"type": "string", "description": "'armed' when a live owner arm binds this session and board, otherwise 'not_armed'."},
              "write_window": {"type": ["object", "null"], "description": "The active write-window operation, or null when no write is in flight."},
              "receipt_count": {"type": "integer", "description": "Receipts chained for this session so far."},
              "pack_status": {"type": "string", "description": "'sealed' once session_close has sealed the pack, otherwise 'open'."},
              "lease_state": {"type": ["string", "null"], "description": "Lease state for the session's board, e.g. 'held' or 'released'."},
              "target_class": {"type": "string", "description": "Adapter-declared target class (fixture or emulator in this build)."}},
             ["state", "board_state", "granted_tiers"]),
        _ANN(True, True)),
    "target_connect": (
        "Connect the session's adapter to its board and scan the "
        "target chain, returning the discovered targets and chain "
        "state (tier T0). Use after session_open and before "
        "target_attest; use register_read, memory_read and "
        "console_read for data once connected. The board's "
        "registry class is re-checked against its adapter's "
        "declared class at connect — a relabelled board refuses "
        "TARGET_MISMATCH. Naming a board other than the session's "
        "refuses BOARD_NOT_IN_MANDATE. Mutating in session state "
        "only: moves the session to CONNECTED and the board to "
        "CONNECTED (unless UNKNOWN); repeating the call is safe "
        "and returns the same shape. No target state is written. "
        "Returns data {connect, targets, chain_state}.",
        {"session_id": _S("Session id returned by session_open."),
         "board_id": _S("Optional board check: when supplied it must be the session's own board. Omit to use the session board.")},
        ["session_id"],
        _ENV({"connect": {"type": "object", "description": "Adapter connect result: connected flag, adapter name and board details as the adapter reports them."},
              "targets": {"type": "array", "description": "Targets found by the chain scan, each with its target id and identity fields."},
              "chain_state": {"type": "string", "description": "Chain scan state reported by the adapter."}},
             ["targets", "chain_state"]),
        _ANN(False, True)),
    "target_attest": (
        "Re-attest the session board's state (tier T0): programmed "
        "hashes, power state, console tail hash, target identity "
        "and the read-only strap state. Use after target_connect, "
        "and again whenever the board is UNKNOWN — writes (tier "
        "T1 and above) refuse REATTESTATION_REQUIRED on an UNKNOWN "
        "board until an attestation completes in the session. "
        "Mutating in session state only: marks the board ATTESTED "
        "and the session ACTIVE and stores the attestation; it "
        "changes nothing on the target itself. Repeating it is "
        "safe. Returns the attestation object as data, including "
        "strap_state.",
        {"session_id": _S("Session id returned by session_open."),
         "board_id": _S("Optional board check: when supplied it must be the session's own board. Omit to use the session board.")},
        ["session_id"],
        _ENV({"board_id": {"type": "string", "description": "Attested board id."},
              "power_state": {"type": "string", "description": "Power state observed at attestation."},
              "strap_state": {"type": "string", "description": "Boot-strap state, read-only in this surface; it can never be set through any tool."}},
             []),
        _ANN(False, True)),
    "register_read": (
        "Read one target register (tier T0) and return its value. "
        "Use for mapped register inspection inside a session; use "
        "memory_read for byte ranges instead. The address must lie "
        "inside the target's address map — an out-of-map address "
        "refuses ADDRESS_OUT_OF_MAP. Addresses are integers; a "
        "hex string such as '0x1000' is also accepted. width is "
        "the read width in bits and must be 8, 16, 32 or 64 "
        "(default 32). Read-only apart from the receipt every call "
        "appends. Returns data {value}.",
        {"session_id": _S("Session id returned by session_open."),
         "target_id": _S("Target id on the session board, as reported by target_connect's chain scan."),
         "address": _I("Register address inside the target address map. Integer form; a '0x'-prefixed hex string is also accepted."),
         "width": _I("Read width in bits: 8, 16, 32 or 64. Defaults to 32.")},
        ["session_id", "target_id", "address"],
        _ENV({"value": {"type": "integer", "description": "Register value at the address."}},
             ["value"]),
        _ANN(True, True)),
    "memory_read": (
        "Read a byte range from target memory (tier T0) and "
        "return it base64-encoded with its SHA-256. Use for "
        "memory inspection inside a session; use register_read "
        "for single mapped registers instead. The whole range "
        "must lie inside the target address map or the read "
        "refuses ADDRESS_OUT_OF_MAP, and length counts against "
        "the mandate's max_read_bytes cap — exceeding it refuses "
        "CAP_EXCEEDED. Read-only apart from the receipt every "
        "call appends; the read's hash is kept as session "
        "evidence. Returns data {bytes_b64, sha256}.",
        {"session_id": _S("Session id returned by session_open."),
         "target_id": _S("Target id on the session board, as reported by target_connect."),
         "address": _I("Start address inside the target address map. Integer form; a '0x'-prefixed hex string is also accepted."),
         "length": _I("Bytes to read; must be positive and within the mandate's max_read_bytes cap.")},
        ["session_id", "target_id", "address", "length"],
        _ENV({"bytes_b64": {"type": "string", "description": "The bytes read, base64-encoded."},
              "sha256": {"type": "string", "description": "SHA-256 of the bytes read."}},
             ["bytes_b64", "sha256"]),
        _ANN(True, True)),
    "console_read": (
        "Read the session board's serial console tail (tier T0) "
        "and return its text with a truncation flag. Use to "
        "observe boot or runtime output; this surface has no "
        "console write or shell of any kind. max_bytes bounds "
        "the returned tail (default 4096). since_receipt is "
        "accepted for interface compatibility but does not "
        "filter the result in this build. Naming a board other "
        "than the session's refuses BOARD_NOT_IN_MANDATE. "
        "Read-only apart from the receipt every call appends. "
        "Returns data {text, truncated}.",
        {"session_id": _S("Session id returned by session_open."),
         "board_id": _S("Optional board check: when supplied it must be the session's own board. Omit to use the session board."),
         "since_receipt": _S("Accepted but not applied in this build: the console tail is returned regardless of this value."),
         "max_bytes": _I("Maximum console bytes to return; defaults to 4096.")},
        ["session_id"],
        _ENV({"text": {"type": "string", "description": "Console tail text."},
              "truncated": {"type": "boolean", "description": "True when the console held more than max_bytes and the tail was cut."}},
             ["text", "truncated"]),
        _ANN(True, True)),
    "artifact_load": (
        "Load a pin-gated artifact (bitstream or ELF) onto a "
        "target inside a write window (tier T1), with readback. "
        "Use to program a target with an approved artifact; use "
        "pin_verify first to check an artifact against its pin "
        "offline without loading. The pin check runs in a fixed "
        "order — pin exists, Herald signature, artifact hash, "
        "class, expiry and revocation, target constraints, and "
        "the pin must be inside the session mandate's pin set — "
        "and one byte of difference from the pinned hash refuses "
        "ARTIFACT_PIN_MISMATCH with no override parameter "
        "anywhere in the surface. The board must be ATTESTED "
        "(writes on an UNKNOWN board refuse "
        "REATTESTATION_REQUIRED) and the load counts against the "
        "mandate's max_loads cap. Mutating: writes the artifact "
        "to the target in fixture/emulator boards in this build. "
        "Returns data {loaded_sha256, readback_sha256, "
        "semantics_note, window_receipts}.",
        {"session_id": _S("Session id returned by session_open."),
         "board_id": _S("The session's board; naming any other board refuses BOARD_NOT_IN_MANDATE."),
         "target_id": _S("Target to load, as reported by target_connect. Optional in the schema; loaders act on the board's addressed target."),
         "artifact_ref": _S("Artifact reference in the bridge's artifact store, e.g. 'art-zcu102-elf'. An absent artifact refuses ARTIFACT_PIN_MISMATCH because nothing can match a pin."),
         "pin_ref": _REF("Herald-signed pin the artifact must match: a pin_id string known to the bridge, or the pin object itself."),
         "artifact_class": _S("Must be 'bitstream' or 'elf'; anything else is refused as an invalid class.")},
        ["session_id", "board_id", "artifact_ref", "pin_ref",
         "artifact_class"],
        _ENV({"loaded_sha256": {"type": "string", "description": "SHA-256 of the artifact as loaded."},
              "readback_sha256": {"type": "string", "description": "SHA-256 read back from the target after the load."},
              "semantics_note": {"type": ["string", "null"], "description": "Adapter note on load semantics, when the adapter supplies one."},
              "window_receipts": {"type": "array", "description": "Receipt ids issued inside the write window."}},
             ["loaded_sha256"]),
        _ANN(False, False)),
    "memory_write": (
        "Write bytes to volatile target memory (tier T1) and "
        "return the written hash. Use for runtime memory changes "
        "inside a session; use persistent_write for boot media "
        "and artifact_load for whole pinned artifacts. The whole "
        "range must lie inside the target address map or the "
        "write refuses ADDRESS_OUT_OF_MAP, the bytes count "
        "against the mandate's max_write_bytes cap, and the "
        "board must be ATTESTED. bytes_b64 must be valid base64 "
        "or the call is refused by name. Mutating but volatile: "
        "the write lives in target memory only and does not "
        "persist across a power cycle. Returns data "
        "{written_sha256}.",
        {"session_id": _S("Session id returned by session_open."),
         "target_id": _S("Target id on the session board, as reported by target_connect."),
         "address": _I("Start address inside the target address map. Integer form; a '0x'-prefixed hex string is also accepted."),
         "bytes_b64": _S("Bytes to write, base64-encoded. Invalid base64 is refused by name.")},
        ["session_id", "target_id", "address", "bytes_b64"],
        _ENV({"written_sha256": {"type": "string", "description": "SHA-256 of the bytes as written."}},
             ["written_sha256"]),
        _ANN(False, False)),
    "target_run": (
        "Run a halted target core from its current state (tier "
        "T1). Use after artifact_load or target_halt to start or "
        "resume execution; use target_halt to stop it again. "
        "Mutating: changes the core's run state on "
        "fixture/emulator targets in this build; nothing else is "
        "altered. Returns data {core_state} with the state after "
        "the run request, e.g. 'running'.",
        {"session_id": _S("Session id returned by session_open."),
         "target_id": _S("Target id on the session board, as reported by target_connect.")},
        ["session_id", "target_id"],
        _ENV({"core_state": {"type": "string", "description": "Core state after the run request, e.g. 'running'."}},
             ["core_state"]),
        _ANN(False, False)),
    "target_halt": (
        "Halt a running target core (tier T1) and return its "
        "state and program counter. Use to stop execution before "
        "inspection, reload or power changes; use target_run to "
        "resume. Mutating: changes the core's run state on "
        "fixture/emulator targets in this build. Returns data "
        "{core_state, pc}.",
        {"session_id": _S("Session id returned by session_open."),
         "target_id": _S("Target id on the session board, as reported by target_connect.")},
        ["session_id", "target_id"],
        _ENV({"core_state": {"type": "string", "description": "Core state after the halt, e.g. 'halted'."},
              "pc": {"type": "string", "description": "Program counter at the halt, as a hex string."}},
             ["core_state"]),
        _ANN(False, False)),
    "power_set": (
        "Set a board's power state — on, off or cycle (tier "
        "T2). Use for controlled power sequencing inside a "
        "session; use target_reset for a target reset that "
        "leaves power alone. Every power act is receipted "
        "before its result is reported. Dead-man bound: a "
        "power call made while a write window is active "
        "refuses POWER_WINDOW_ACTIVE and is never queued — "
        "power is never cut mid-write. A cycle counts against "
        "the mandate's max_power_cycles cap. Mutating: changes "
        "board power on fixture/emulator boards in this build. "
        "Returns data {prior_state, new_state}.",
        {"session_id": _S("Session id returned by session_open."),
         "board_id": _S("The session's board; naming any other board refuses BOARD_NOT_IN_MANDATE."),
         "state": _S("Desired power state: 'on', 'off' or 'cycle'. Any other value is refused by name.")},
        ["session_id", "board_id", "state"],
        _ENV({"prior_state": {"type": "string", "description": "Power state before the act."},
              "new_state": {"type": "string", "description": "Power state after the act."}},
             ["new_state"]),
        _ANN(False, False)),
    "target_reset": (
        "Reset a target, as a full system reset or a core-only "
        "reset (tier T2), receipted exactly like power_set. "
        "Use to restart a target without changing power; use "
        "power_set when power itself must change. Like "
        "power_set, a reset requested inside an active write "
        "window refuses POWER_WINDOW_ACTIVE and is never "
        "queued. kind defaults to 'system'; any other value "
        "than 'system' or 'core' is refused by name. Mutating "
        "on fixture/emulator targets in this build. Returns "
        "data {reset, target_id, reset_receipt}.",
        {"session_id": _S("Session id returned by session_open."),
         "board_id": _S("Optional board check: when supplied it must be the session's own board. Omit to use the session board."),
         "target_id": _S("Target id on the session board, as reported by target_connect."),
         "kind": _S("Reset kind: 'system' or 'core'. Defaults to 'system'.")},
        ["session_id", "target_id"],
        _ENV({"reset": {"type": "string", "description": "Reset kind performed: 'system' or 'core'."},
              "target_id": {"type": "string", "description": "Target that was reset."},
              "reset_receipt": {"type": "string", "description": "Note binding the reset to this operation's receipt in the session pack."}},
             ["reset", "target_id"]),
        _ANN(False, False)),
    "persistent_write": (
        "Write a pin-gated artifact to a board's persistent "
        "boot media (tier T3, the highest tier) with a "
        "verify-readback. Use only for deliberate boot-media "
        "changes; use artifact_load for volatile target loads "
        "and memory_write for RAM. Four preconditions are all "
        "verified at use time: a live owner arm binding this "
        "session and board (agents cannot arm — arming is an "
        "owner act outside the tool surface; without it the "
        "call refuses TIER_NOT_ARMED), a completed pre-write "
        "capture of the media taken in this session (the "
        "capture runs inside this tool's flow through the "
        "bridge; it is not a separate tool), a recorded "
        "recovery path for the board/media, and the same "
        "one-byte pin rule as artifact_load — any hash "
        "difference refuses ARTIFACT_PIN_MISMATCH. Mutating "
        "and persistent: the write overwrites boot media and "
        "survives power cycles, which is why the capture and "
        "recovery path are mandatory. Fuse programming and "
        "voltage/PMIC configuration have no tool here at all "
        "and refuse permanently by name at the boundary. "
        "Returns data {written_sha256, capture_ref}.",
        {"session_id": _S("Session id returned by session_open."),
         "board_id": _S("The session's board; naming any other board refuses BOARD_NOT_IN_MANDATE."),
         "media": _S("Boot-media id on the session board, as recorded in the board's registry entry."),
         "artifact_ref": _S("Artifact reference in the bridge's artifact store; its bytes must match the pin exactly."),
         "pin_ref": _REF("Herald-signed pin for this boot image: a pin_id string known to the bridge, or the pin object itself.")},
        ["session_id", "board_id", "media", "artifact_ref",
         "pin_ref"],
        _ENV({"written_sha256": {"type": "string", "description": "SHA-256 of the image as written to the media."},
              "capture_ref": {"type": "string", "description": "Id of the pre-write capture this write relied on."}},
             ["written_sha256", "capture_ref"]),
        _ANN(False, False, True)),
    "session_close": (
        "Close a session, release its board lease and seal the "
        "evidence pack for the whole session. Use when work is "
        "done; afterwards use pack_verify and gate_run on the "
        "sealed pack. The close operation is itself receipted "
        "into the pack before sealing. A session whose pack "
        "cannot seal does not report closed — the call returns "
        "a receipted EVIDENCE_PACK_FAILURE refusal and the "
        "session stays open. Closing is final: the lease is "
        "released, any owner arm for the session is deleted, "
        "and no further operations are accepted on the "
        "session_id. Returns data {pack_id, pack_sha256, "
        "gate_ready, target_class}.",
        {"session_id": _S("Session id returned by session_open."),
         "reason": _S("Free-text close reason recorded with the close operation. Optional.")},
        ["session_id"],
        _ENV({"pack_id": {"type": "string", "description": "Sealed pack id; the key for pack_verify and gate_run."},
              "pack_sha256": {"type": "string", "description": "Seal hash of the sealed pack."},
              "gate_ready": {"type": "boolean", "description": "True when the sealed pack is ready for gate_run."},
              "target_class": {"type": "string", "description": "Target class sealed into the pack (fixture or emulator in this build)."}},
             ["pack_id", "pack_sha256"]),
        _ANN(False, False)),
    "pin_verify": (
        "Verify one artifact against its Herald-signed pin, "
        "offline and without a session: pin signature, artifact "
        "hash equality, artifact class, and pin expiry and "
        "revocation, checked in that order. Use to check an "
        "artifact before artifact_load; use pin_show to read "
        "the pin record and pin_status for its lifecycle state "
        "only. Runnable by third parties holding the artifact "
        "and pin — no session or lease is involved. Read-only "
        "apart from the receipt every call appends. A failed "
        "check is reported in the returned verdict rather than "
        "hidden: data carries the refusal code as its verdict. "
        "Returns data {ok, verdict, artifact_sha256, pin_id, "
        "approver} on success, where verdict is PIN_VALID.",
        {"artifact_ref": _S("Artifact reference in the bridge's artifact store. An absent artifact fails verification because nothing can match the pin."),
         "pin_ref": _REF("Herald-signed pin to verify against: a pin_id string known to the bridge, or the pin object itself.")},
        ["artifact_ref", "pin_ref"],
        _ENV({"ok": {"type": "boolean", "description": "True when the artifact verifies against the pin."},
              "verdict": {"type": "string", "description": "'PIN_VALID' on success; on failure, the named refusal code (e.g. ARTIFACT_PIN_MISMATCH, PIN_SIGNATURE_INVALID, PIN_EXPIRED, PIN_REVOKED)."},
              "artifact_sha256": {"type": "string", "description": "SHA-256 of the verified artifact; present on success."},
              "pin_id": {"type": "string", "description": "Id of the pin checked."},
              "approver": {"type": "string", "description": "Approver identity recorded on the pin; present on success."}},
             ["verdict"]),
        _ANN(True, True)),
    "pin_show": (
        "Render one pin record with its Herald signature "
        "status and its full target-constraint set. Use to "
        "inspect what a pin demands before pin_verify or a "
        "load; use pin_status when only the lifecycle state is "
        "needed. Read-only apart from the receipt every call "
        "appends: the record is returned as stored, with "
        "signature_status computed fresh as 'valid' or "
        "'invalid'. Returns data {pin, signature_status, "
        "target_constraints}.",
        {"pin_ref": _REF("Pin to render: a pin_id string known to the bridge, or the pin object itself. An unknown string refuses NO_PIN.")},
        ["pin_ref"],
        _ENV({"pin": {"type": "object", "description": "The full pin record as stored."},
              "signature_status": {"type": "string", "description": "'valid' or 'invalid' for the pin's Herald signature, computed at call time."},
              "target_constraints": {"type": "object", "description": "Constraints the pin imposes on targets: board, board revision range and silicon revision where recorded."}},
             ["pin", "signature_status"]),
        _ANN(True, True)),
    "pin_status": (
        "Report one pin's lifecycle state: active, expired or "
        "revoked, with the revocation source named when "
        "revoked. Use for a quick state check; use pin_show "
        "for the full record and pin_verify to verify an "
        "artifact against the pin. Read-only apart from the "
        "receipt every call appends; the state is computed "
        "from the pin's expiry and the bridge's revocation "
        "set at call time. Returns data {pin_id, state, "
        "revocation_source}, where revocation_source is null "
        "unless the state is revoked.",
        {"pin_ref": _REF("Pin to report on: a pin_id string known to the bridge, or the pin object itself. An unknown string refuses NO_PIN.")},
        ["pin_ref"],
        _ENV({"pin_id": {"type": "string", "description": "Id of the pin reported on."},
              "state": {"type": "string", "description": "'active', 'expired' or 'revoked'."},
              "revocation_source": {"type": ["string", "null"], "description": "Where the revocation came from; null unless state is 'revoked'."}},
             ["pin_id", "state"]),
        _ANN(True, True)),
    "gate_run": (
        "Run an assertion set over one sealed evidence pack "
        "and return a signed gate verdict: BOOT_VERIFIED when "
        "every assertion passes, BOOT_UNVERIFIED with the "
        "failing assertions named otherwise. Use after "
        "session_close seals a pack; use pack_verify for "
        "structural pack validity without assertions and "
        "gate_assertions_check to validate the set itself "
        "first. The pack's receipt chain is always evaluated, "
        "an assertion type outside the closed vocabulary "
        "refuses ASSERTION_TYPE_UNKNOWN, and the verdict "
        "inherits the pack's target_class — in this build "
        "packs come only from fixture and emulator boards, so "
        "no verdict here certifies real hardware. Read-only "
        "apart from the receipt every call appends. Returns "
        "data {pack_id, set_id, verdict, per_assertion, "
        "pack_sha256, target_class, gate_version, at, "
        "verdict_id, sha256}.",
        {"pack_ref": _REF("Sealed pack to judge: a pack_id string known to the bridge, or the pack object itself (a pack object plus the bridge public key is all an offline check needs)."),
         "assertion_set_ref": _REF("Assertion set to run: a set_id string known to the bridge, or the set object itself. Every assertion type must be in the closed vocabulary.")},
        ["pack_ref", "assertion_set_ref"],
        _ENV({"pack_id": {"type": "string", "description": "Id of the pack judged."},
              "set_id": {"type": "string", "description": "Id of the assertion set applied."},
              "verdict": {"type": "string", "description": "'BOOT_VERIFIED' or 'BOOT_UNVERIFIED'."},
              "per_assertion": {"type": "array", "description": "Per-assertion results: the assertion, PASS or FAIL, and its evidence reference."},
              "pack_sha256": {"type": "string", "description": "Seal hash of the judged pack."},
              "target_class": {"type": "string", "description": "Target class inherited from the pack (fixture or emulator in this build)."},
              "verdict_id": {"type": "string", "description": "Id of this verdict record."},
              "sha256": {"type": "string", "description": "Hash of the verdict record itself."}},
             ["verdict", "per_assertion"]),
        _ANN(True, True)),
    "pack_verify": (
        "Verify one sealed evidence pack's structure offline: "
        "recompute its receipt chain, verify the seal "
        "signature, and check gap and refusal completeness. "
        "Use to establish a pack is intact before gate_run; "
        "gate_run adds assertions on top of the same validity "
        "check. Runnable by third parties — a pack object "
        "plus the bridge public key suffices. Read-only apart "
        "from the receipt every call appends. Returns data "
        "{ok, verdict, reason, pack_id, target_class}, where "
        "verdict is PACK_VALID or PACK_INVALID with the "
        "reason named.",
        {"pack_ref": _REF("Sealed pack to verify: a pack_id string known to the bridge, or the pack object itself.")},
        ["pack_ref"],
        _ENV({"ok": {"type": "boolean", "description": "True when the pack verifies."},
              "verdict": {"type": "string", "description": "'PACK_VALID' or 'PACK_INVALID'."},
              "reason": {"type": ["string", "null"], "description": "Why the pack is invalid; null or empty when valid."},
              "pack_id": {"type": "string", "description": "Id of the pack verified."},
              "target_class": {"type": "string", "description": "Target class recorded in the pack (fixture or emulator in this build)."}},
             ["verdict"]),
        _ANN(True, True)),
    "gate_assertions_check": (
        "Validate one assertion set against the closed "
        "assertion vocabulary without running it: every "
        "assertion type must be a known type, and unknown "
        "types are named in the result. Use before gate_run "
        "to fail fast on a malformed set; gate_run refuses "
        "unknown types with ASSERTION_TYPE_UNKNOWN when they "
        "reach it unchecked. Read-only apart from the "
        "receipt every call appends. Returns data {valid, "
        "unknown_assertions, set_id, assertion_count}; note "
        "that through this server an invalid set is also "
        "surfaced as a refusal naming ASSERTION_TYPE_UNKNOWN, "
        "while a valid set returns data with valid true.",
        {"assertion_set_ref": _REF("Assertion set to validate: a set_id string known to the bridge, or the set object itself.")},
        ["assertion_set_ref"],
        _ENV({"valid": {"type": "boolean", "description": "True when every assertion type is in the closed vocabulary."},
              "unknown_assertions": {"type": "array", "description": "Assertion types not in the vocabulary; empty when valid."},
              "set_id": {"type": ["string", "null"], "description": "Id of the set validated."},
              "assertion_count": {"type": "integer", "description": "How many assertions the set carries."}},
             ["valid", "unknown_assertions"]),
        _ANN(True, True)),
}

SESSION_TOOLS = (
    "session_status", "target_connect", "target_attest",
    "register_read", "memory_read", "console_read", "artifact_load",
    "memory_write", "target_run", "target_halt", "power_set",
    "target_reset", "persistent_write", "session_close",
)

# §6.4 denylist — parameter semantics that must never appear.
# Mapped to the refusal that names the act where a permanent code
# exists (§3.1); raw-escape params refuse OP_NOT_IN_MANDATE (§3.2.3).
DENIED_PARAM_REFUSALS = {
    "voltage": "PERMANENT_REFUSED_PMIC",
    "pmic": "PERMANENT_REFUSED_PMIC",
    "voltage_set": "PERMANENT_REFUSED_PMIC",
    "set_voltage": "PERMANENT_REFUSED_PMIC",
    "fuse": "PERMANENT_REFUSED_FUSE",
    "efuse": "PERMANENT_REFUSED_FUSE",
    "strap_set": "BOOT_MODE_PHYSICAL",
    "tcl": "OP_NOT_IN_MANDATE",
    "script": "OP_NOT_IN_MANDATE",
    "command": "OP_NOT_IN_MANDATE",
    "shell": "OP_NOT_IN_MANDATE",
    "exec": "OP_NOT_IN_MANDATE",
    "xsdb": "OP_NOT_IN_MANDATE",
    "raw": "OP_NOT_IN_MANDATE",
}

# Names that must never resolve as tools (§6.3): fuzzed/permanent-op
# names refuse as unknown tools at the transport (H-11).
FORBIDDEN_TOOL_NAMES = {
    "fuse_program", "program_fuse", "efuse_program", "pmic_config",
    "voltage_set", "set_voltage", "strap_set", "boot_mode_set",
    "exec_tcl", "tcl", "xsdb_console", "shell", "raw_command",
    "tier_arm", "bench_freeze_set", "mandate_revoke", "lease_release",
    "pack_export", "persistent_capture",
}


def tool_list():
    return [{"name": name, "description": desc,
             "inputSchema": {"type": "object", "properties": props,
                             "required": required},
             "outputSchema": out, "annotations": ann}
            for name, (desc, props, required, out, ann)
            in TOOLS.items()]


def _result(rid, payload, is_error=False):
    return {"jsonrpc": "2.0", "id": rid, "result": {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "isError": is_error}}


def _boundary_refusal(rid, tool, args, code, detail):
    out = BRIDGE._log_call(tool, args, lambda: (_ for _ in ()).throw(
        Refusal(code, detail)))
    return _result(rid, out, is_error=True)


def dispatch(tool, args):
    """Route a validated call. Session ops go through the engine's
    receipted dispatch; Pin/Gate are standalone (§7.2/§8.2)."""
    if tool == "bench_discover":
        return BRIDGE.bench_discover(args)
    if tool == "session_open":
        return BRIDGE.session_open(args)
    if tool in SESSION_TOOLS:
        return BRIDGE.call_session_op(tool, args)
    return bridge_mod.STANDALONE_TOOLS[tool](BRIDGE, args)


def _envelope_error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": code, "message": message}}


def handle(req: dict):
    # Envelope guards (bench D-3 fix, house hygiene): every
    # wrong-shape envelope input — non-object request, non-string
    # method, params as str/int/list, tool name as list/dict —
    # refuses with a structured -32600/-32602 and the server NEVER
    # dies; no exception escapes handle(), and the bridge receipt /
    # audit chains are untouched by envelope refusals.
    if not isinstance(req, dict):
        return _envelope_error(
            None, -32600,
            "invalid request: the JSON-RPC envelope must be an "
            "object; refused, server alive")
    method, rid = req.get("method", ""), req.get("id")
    if not isinstance(method, str):
        return _envelope_error(
            rid, -32600,
            "invalid request: method must be a string; refused, "
            "server alive")
    if method == "initialize":
        init_params = req.get("params")
        protocol = init_params.get("protocolVersion",
                                   "2025-03-26") \
            if isinstance(init_params, dict) else "2025-03-26"
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": protocol,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "eclipse-proving",
                           "version": "0.1.0"}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"tools": tool_list()}}
    if method == "tools/call":
        params = req.get("params")
        if not isinstance(params, dict):
            return _envelope_error(
                rid, -32602,
                f"invalid params: params must be an object (got "
                f"{type(params).__name__}); refused, server alive")
        name = params.get("name", "")
        if not isinstance(name, str):
            return _envelope_error(
                rid, -32602,
                f"invalid params: tool name must be a string (got "
                f"{type(name).__name__}); refused, server alive")
        args = params.get("arguments", {})
        if name in FORBIDDEN_TOOL_NAMES or name not in TOOLS:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602,
                "message": f"unknown tool {name}: the Proving "
                           "surface is exactly the 22 tools of §6; "
                           "permanent ops and admin verbs do not "
                           "exist here (§6.3/§6.4)"}}
        try:
            engine.require_container_param(args, "arguments", "object")
        except engine.ToolError as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602, "message": str(e)}}
        _, props, _, _, _ = TOOLS[name]
        for key in args:
            if key in DENIED_PARAM_REFUSALS:
                return _boundary_refusal(
                    rid, name, args, DENIED_PARAM_REFUSALS[key],
                    f"parameter {key!r} is on the §6.4 denylist; "
                    "the act it names does not exist in this surface")
            if key not in props:
                return _boundary_refusal(
                    rid, name, args, "ARGUMENT_UNKNOWN",
                    f"parameter {key!r} is not in the {name} schema; "
                    "refused at the boundary, receipted (§6.4)")
            # Reference-type guard at the boundary: a schema "string"
            # param arriving as a non-string refuses BY NAME before
            # any lookup — never a downstream TypeError from a dict
            # key or an unhashable ref (house fuzz lesson).
            if props[key].get("type") == "string" and \
                    not isinstance(args[key], str):
                return _boundary_refusal(
                    rid, name, args, "ARGUMENT_TYPE",
                    f"parameter {key!r} must be a string (got "
                    f"{type(args[key]).__name__}); refused by name, "
                    "never coerced")
        out = dispatch(name, args)
        return _result(rid, out, is_error=not out.get("ok", False))
    return {"jsonrpc": "2.0", "id": rid, "error": {
        "code": -32601, "message": f"method not found: {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Last-resort envelope guard: handle() refuses every known
        # wrong shape itself; if anything unforeseen still raises,
        # the stdio server answers -32600 and stays alive (D-3).
        try:
            resp = handle(req)
        except Exception:
            resp = _envelope_error(
                req.get("id") if isinstance(req, dict) else None,
                -32600,
                "invalid request envelope; refused, server alive")
        req_id = req.get("id") if isinstance(req, dict) else None
        if resp is not None and (req_id is not None or
                                 not isinstance(req, dict)):
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
