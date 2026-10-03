#!/usr/bin/env python3
"""FTP(S) deploy for GitHub Actions — uploads only what changed since the last deploy.

Reads .github/deploy.json:
  source            directory to upload (default ".")
  exclude           gitignore-style patterns never uploaded (relative to source)
  protect           patterns never uploaded NOR deleted on the server (server-only files)
  map               {"local/dir/": "remote/dir/"} extra copies of a subtree to another remote path
  maintenance_flag  remote file created during upload and removed afterwards (optional)

State lives on the server in .deploy-manifest.json (path -> sha1). A file is uploaded when
its hash differs from the manifest; a file is deleted only when it was deployed before and
no longer exists in the source at all (excluded/protected files are never deleted).

Env: FTP_HOST, FTP_USER, FTP_PASSWORD, FTP_DIR (default "/"), DEPLOY_FULL=1 to resend all,
DEPLOY_DRY=1 to only print the plan. Writes a summary to $DEPLOY_SUMMARY (JSON) if set.
"""
import fnmatch
import ftplib
import hashlib
import io
import json
import os
import posixpath
import queue
import socket
import sys
import threading
import time

MANIFEST = ".deploy-manifest.json"
WORKERS = int(os.environ.get("DEPLOY_WORKERS", "6"))
ALWAYS_EXCLUDE = [".git/", ".github/", ".ftp-deploy.json", ".ftp-deploy-sync-state.json",
                  MANIFEST, "PRISTUPY*.md", "PRISTUPY*.txt", ".env", ".env.*", ".DS_Store",
                  ".playwright-mcp/", ".claude/", "node_modules/"]


class ReusedSslFTP(ftplib.FTP_TLS):
    """WEDOS vsftpd requires the data channel to reuse the control TLS session."""

    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host,
                                            session=self.sock.session)
        return conn, size


def connect():
    for attempt in range(5):
        try:
            ftp = ReusedSslFTP(timeout=60)
            ftp.connect(os.environ["FTP_HOST"], int(os.environ.get("FTP_PORT", "21")))
            ftp.login(os.environ["FTP_USER"], os.environ["FTP_PASSWORD"])
            ftp.prot_p()
            ftp.set_pasv(True)
            return ftp
        except ftplib.error_perm as e:
            # 530 = wrong login; retrying would get the runner IP blocked by WEDOS
            sys.exit(f"FTP login refused: {e}")
        except (OSError, ftplib.Error) as e:
            print(f"connect failed ({e}), retry {attempt + 1}/5", flush=True)
            time.sleep(3 * (attempt + 1))
    sys.exit("FTP connect failed")


def matches(rel, patterns):
    """gitignore-ish: 'dir/' matches the directory and everything below it,
    a pattern without '/' matches any path component, otherwise match from the root."""
    parts = rel.split("/")
    for p in patterns:
        p = p.strip()
        if not p or p.startswith("#"):
            continue
        anchored = p.startswith("/")
        p = p.lstrip("/")
        if p.endswith("/"):
            d = p.rstrip("/")
            for i in range(1, len(parts)):
                prefix = "/".join(parts[:i])
                if fnmatch.fnmatchcase(prefix, d) or (not anchored and "/" not in d
                                                      and fnmatch.fnmatchcase(parts[i - 1], d)):
                    return True
        elif "/" in p or anchored:
            if fnmatch.fnmatchcase(rel, p):
                return True
        elif any(fnmatch.fnmatchcase(x, p) for x in parts):
            return True
    return False


def sha1(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(cfg):
    """remote path -> local path for everything that should be on the server."""
    source = os.path.normpath(cfg.get("source", "."))
    exclude = ALWAYS_EXCLUDE + cfg.get("exclude", [])
    protect = cfg.get("protect", [])
    mapping = cfg.get("map", {})
    files, present = {}, set()
    for root, dirs, names in os.walk(source):
        dirs[:] = [d for d in dirs if d != ".git"]
        for n in names:
            local = os.path.join(root, n)
            if os.path.islink(local):
                continue
            rel = os.path.relpath(local, source).replace(os.sep, "/")
            present.add(rel)
            target, mapped = rel, False
            for src, dst in mapping.items():
                if rel.startswith(src):
                    target, mapped = dst + rel[len(src):], True
                    present.add(target)
                    break
            # a mapped file is judged by where it lands, not where it lives in the repo
            if matches(target if mapped else rel, exclude) or matches(target, protect):
                continue
            files[target] = local
    return files, present, protect


class Pool:
    """A few parallel FTP connections — WEDOS costs ~1 s per file, one connection is too slow."""

    def __init__(self, n):
        self.q = queue.Queue()
        self.errors = []
        self.lock = threading.Lock()
        self.dirs = set()
        self.threads = [threading.Thread(target=self.work, daemon=True) for _ in range(n)]
        for t in self.threads:
            t.start()

    def work(self):
        ftp = None
        while True:
            job = self.q.get()
            if job is None:
                break
            for attempt in range(3):
                try:
                    if ftp is None:
                        ftp = connect()
                        ftp.cwd(BASE)
                    job(ftp)
                    break
                except (OSError, EOFError, ftplib.Error) as e:
                    try:
                        ftp.close()
                    except Exception:
                        pass
                    ftp = None
                    if attempt == 2:
                        with self.lock:
                            self.errors.append(f"{getattr(job, 'label', '?')}: {e}")
            self.q.task_done()
        if ftp:
            try:
                ftp.quit()
            except Exception:
                pass

    def put(self, job):
        self.q.put(job)

    def close(self):
        self.q.join()
        for _ in self.threads:
            self.q.put(None)
        for t in self.threads:
            t.join()


def ensure_dir(ftp, d, known):
    if not d or d in known:
        return
    ensure_dir(ftp, posixpath.dirname(d), known)
    try:
        ftp.mkd(d)
        try:
            ftp.sendcmd(f"SITE CHMOD 755 {d}")
        except ftplib.Error:
            pass
    except ftplib.error_perm:
        pass  # 550 = already exists
    known.add(d)


def make_upload(remote, local, size):
    def job(ftp):
        with open(local, "rb") as f:
            ftp.storbinary(f"STOR {remote}", f)
        try:
            ftp.sendcmd(f"SITE CHMOD 644 {remote}")
        except ftplib.Error:
            pass
        got = ftp.size(remote)
        if got != size:
            raise ftplib.Error(f"size mismatch {got} != {size}")
    job.label = remote
    return job


def make_delete(remote):
    def job(ftp):
        try:
            ftp.delete(remote)
        except ftplib.error_perm:
            pass  # already gone
    job.label = "rm " + remote
    return job


def baseline(files, hashes):
    """Download every source file from the server, report what differs and write a manifest
    of the identical ones, so the first real deploy only sends what really changed."""
    same, differ, missing, eol = {}, [], [], []
    lock = threading.Lock()

    def make_check(r):
        def job(ftp):
            buf = io.BytesIO()
            try:
                ftp.retrbinary(f"RETR {r}", buf.write)
            except ftplib.error_perm:
                with lock:
                    missing.append(r)
                return
            remote = buf.getvalue()
            with lock:
                if hashlib.sha1(remote).hexdigest() == hashes[r]:
                    same[r] = hashes[r]
                elif b"\r\n" in remote and remote.replace(b"\r\n", b"\n") == open(files[r], "rb").read():
                    same[r] = hashes[r]  # only CRLF line endings from an old upload
                    eol.append(r)
                else:
                    differ.append(r)
        job.label = r
        return job

    pool = Pool(WORKERS)
    for r in files:
        pool.put(make_check(r))
    pool.close()
    print(f"same {len(same)} (of which only CRLF {len(eol)}), different {len(differ)}, "
          f"missing on server {len(missing)}")
    for r in sorted(differ):
        print("  ~", r)
    for r in sorted(missing):
        print("  +", r)
    for e in pool.errors:
        print("  !", e)
    if os.environ.get("DEPLOY_DRY") != "1" and not pool.errors:
        ftp = connect()
        ftp.cwd(BASE)
        ftp.storbinary(f"STOR {MANIFEST}", io.BytesIO(json.dumps(same, indent=0).encode()))
        try:
            ftp.sendcmd(f"SITE CHMOD 600 {MANIFEST}")
        except ftplib.Error:
            pass
        ftp.quit()
        print("manifest written")


def main():
    global BASE
    cfg_path = os.environ.get("DEPLOY_CONFIG", ".github/deploy.json")
    cfg = json.load(open(cfg_path)) if os.path.exists(cfg_path) else {}
    BASE = os.environ.get("FTP_DIR", "/") or "/"
    full = os.environ.get("DEPLOY_FULL") == "1"
    dry = os.environ.get("DEPLOY_DRY") == "1"

    files, present, protect = collect(cfg)
    hashes = {r: sha1(l) for r, l in files.items()}

    ftp = connect()
    ftp.cwd(BASE)
    buf = io.BytesIO()
    try:
        ftp.retrbinary(f"RETR {MANIFEST}", buf.write)
        old = json.loads(buf.getvalue() or b"{}")
    except ftplib.error_perm:
        old = {}
    first = not old

    if os.environ.get("DEPLOY_BASELINE") == "1":
        ftp.quit()
        return baseline(files, hashes)

    upload = sorted(r for r, h in hashes.items() if full or old.get(r) != h)
    delete = sorted(r for r in old if r not in present and not matches(r, protect))
    print(f"{len(files)} files in source, {len(upload)} to upload, {len(delete)} to delete"
          + (" (first deploy, full upload)" if first else ""), flush=True)
    for r in upload[:200]:
        print("  +", r)
    for r in delete:
        print("  -", r)
    if dry:
        return

    flag = cfg.get("maintenance_flag")
    if flag and (upload or delete):
        ftp.storbinary(f"STOR {flag}", io.BytesIO(b"deploy\n"))

    try:
        known = set()
        for d in sorted({posixpath.dirname(r) for r in upload}):
            ensure_dir(ftp, d, known)
        ftp.quit()

        pool = Pool(WORKERS)
        for r in upload:
            pool.put(make_upload(r, files[r], os.path.getsize(files[r])))
        for r in delete:
            pool.put(make_delete(r))
        pool.close()
    finally:
        ftp = connect()
        ftp.cwd(BASE)
        if flag and (upload or delete):
            try:
                ftp.delete(flag)
            except ftplib.error_perm:
                pass

    failed = {e.split(":")[0] for e in pool.errors}
    manifest = {r: h for r, h in hashes.items() if r not in failed}
    # keep the old hash for files that failed so they are retried next time
    for r in failed:
        if r in old:
            manifest[r] = old[r]
    ftp.storbinary(f"STOR {MANIFEST}", io.BytesIO(json.dumps(manifest, indent=0).encode()))
    try:
        ftp.sendcmd(f"SITE CHMOD 600 {MANIFEST}")
    except ftplib.Error:
        pass
    ftp.quit()

    summary = {"uploaded": len(upload) - len(failed), "deleted": len(delete),
               "failed": pool.errors, "first": first}
    if os.environ.get("DEPLOY_SUMMARY"):
        json.dump(summary, open(os.environ["DEPLOY_SUMMARY"], "w"))
    print(json.dumps(summary, ensure_ascii=False))
    if pool.errors:
        sys.exit(f"{len(pool.errors)} files failed")


if __name__ == "__main__":
    socket.setdefaulttimeout(120)
    main()
