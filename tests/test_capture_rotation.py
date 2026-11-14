"""Rotation-aware audit reads (live capture). auditd renames audit.log to
audit.log.N; a window anchor taken before a rotation must still splice back
the exact bytes from the rotated files — including when two rotations
happened inside one window (the bug that silently lost one technique's
events on a busy host)."""

from sigdiff import capture
from sigdiff.capture import Capture


def _mk(path, text):
    path.write_text(text)
    return path


def _anchor(path):
    st = path.stat()
    return (st.st_ino, st.st_size)


def _chain(tmp, monkeypatch):
    monkeypatch.setattr(capture, "AUDIT_LOG", str(tmp / "audit.log"))
    return tmp / "audit.log"


def test_no_rotation_reads_tail(tmp_path, monkeypatch):
    cur = _mk(_chain(tmp_path, monkeypatch), "AAAAhead\nBBBB\n")
    cap = Capture(workdir=str(tmp_path / "work"))
    off = _anchor(cur)
    cur.write_text(cur.read_text() + "CCCC\n")
    assert cap.read_audit_since(off) == "CCCC\n"


def test_one_rotation_splices(tmp_path, monkeypatch):
    cur = _mk(_chain(tmp_path, monkeypatch), "0123456")  # 8-byte log
    cap = Capture(workdir=str(tmp_path / "work"))
    off = _anchor(cur)  # inode of the live file, offset 7
    cur.write_text(cur.read_text() + "9")  # '01234567'
    cur.rename(tmp_path / "audit.log.1")   # auditd's rename: inode survives
    _mk(cur, "abc")                        # new current file
    assert cap.read_audit_since(off) == "9abc"


def test_two_rotations_anchor_in_second(tmp_path, monkeypatch):
    cur = _mk(_chain(tmp_path, monkeypatch), "HEAD0")
    cap = Capture(workdir=str(tmp_path / "work"))
    off = _anchor(cur)  # offset 5 in the file that becomes .2 two rotations later
    cur.write_text("HEAD01")
    cur.rename(tmp_path / "audit.log.1")
    _mk(cur, "M_I_D")
    mid_off = _anchor(cur)
    cur.write_text("M_I_D2")
    (tmp_path / "audit.log.1").rename(tmp_path / "audit.log.2")  # auditd shift first
    cur.rename(tmp_path / "audit.log.1")
    _mk(cur, "tail")
    got = cap.read_audit_since(off)
    assert got == "1" + "M_I_D2" + "tail"  # anchor tail, whole .1 era, current
    assert cap.read_audit_since(mid_off) == "2tail"


def test_anchor_rotated_away_is_over_inclusive(tmp_path, monkeypatch):
    cur = _mk(_chain(tmp_path, monkeypatch), "GONE")
    cap = Capture(workdir=str(tmp_path / "work"))
    cur.rename(tmp_path / "audit.log.1")
    _mk(cur, "new-era")
    # an anchor whose file aged out of num_logs: no chain member can carry an
    # inode this far out of range, so the fallback is deterministic — every
    # surviving rotation is read whole (over-inclusive, never a silent loss)
    got = cap.read_audit_since((999999999999, 2))
    assert got == "GONEnew-era"
