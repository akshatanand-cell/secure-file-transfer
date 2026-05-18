import { useState, useCallback, useRef } from "react";

const PHASES = ["encrypt", "transfer", "decrypt"];

function useFileEncryption() {
  const [key, setKey] = useState(null);
  const [nonce, setNonce] = useState(null);
  const [encryptedBlob, setEncryptedBlob] = useState(null);
  const [originalName, setOriginalName] = useState("");

  async function generateKey() {
    return await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  }

  async function encryptFile(file) {
    const cryptoKey = await generateKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const buffer = await file.arrayBuffer();
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, buffer);
    const rawKey = await crypto.subtle.exportKey("raw", cryptoKey);
    setKey(btoa(String.fromCharCode(...new Uint8Array(rawKey))));
    setNonce(btoa(String.fromCharCode(...iv)));
    setEncryptedBlob(new Blob([encrypted]));
    setOriginalName(file.name);
    return { keyB64: btoa(String.fromCharCode(...new Uint8Array(rawKey))), nonceB64: btoa(String.fromCharCode(...iv)) };
  }

  async function decryptFile(encFile, keyB64, nonceB64) {
    const keyBytes = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(nonceB64), c => c.charCodeAt(0));
    const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    const buffer = await encFile.arrayBuffer();
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, buffer);
    return new Blob([decrypted]);
  }

  return { key, nonce, encryptedBlob, originalName, encryptFile, decryptFile };
}

function DropZone({ onFile, label, accept }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef();

  const handle = (file) => { if (file) onFile(file); };
  const onDrop = (e) => { e.preventDefault(); setDragging(false); handle(e.dataTransfer.files[0]); };

  return (
    <div
      onClick={() => inputRef.current.click()}
      onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      style={{
        border: `2px dashed ${dragging ? "#00f5d4" : "#334155"}`,
        borderRadius: 12, padding: "32px 24px", textAlign: "center",
        cursor: "pointer", background: dragging ? "rgba(0,245,212,0.04)" : "rgba(15,23,42,0.5)",
        transition: "all 0.2s", color: dragging ? "#00f5d4" : "#64748b",
        fontSize: 14, userSelect: "none"
      }}
    >
      <div style={{ fontSize: 32, marginBottom: 8 }}>📂</div>
      <div style={{ fontWeight: 600, color: "#94a3b8" }}>{label}</div>
      <div style={{ marginTop: 4, fontSize: 12 }}>drag & drop or click to browse</div>
      <input ref={inputRef} type="file" accept={accept} style={{ display: "none" }}
        onChange={e => handle(e.target.files[0])} />
    </div>
  );
}

function StatusLog({ logs }) {
  const endRef = useRef();
  return (
    <div style={{
      background: "#020617", borderRadius: 10, padding: "14px 16px",
      fontFamily: "monospace", fontSize: 12, color: "#22d3ee",
      maxHeight: 160, overflowY: "auto", lineHeight: 1.7,
      border: "1px solid #1e293b"
    }}>
      {logs.length === 0 && <span style={{ color: "#475569" }}>// output will appear here</span>}
      {logs.map((l, i) => <div key={i} style={{ color: l.startsWith("✅") ? "#4ade80" : l.startsWith("❌") ? "#f87171" : "#22d3ee" }}>{l}</div>)}
      <div ref={endRef} />
    </div>
  );
}

function KeyBadge({ label, value }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); };
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ fontSize: 11, color: "#64748b", marginBottom: 4 }}>{label}</div>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <div style={{
          flex: 1, background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8,
          padding: "8px 12px", fontFamily: "monospace", fontSize: 11, color: "#7dd3fc",
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
        }}>{value}</div>
        <button onClick={copy} style={{
          background: copied ? "#166534" : "#1e293b", color: copied ? "#4ade80" : "#94a3b8",
          border: "none", borderRadius: 8, padding: "8px 14px", cursor: "pointer",
          fontSize: 11, fontWeight: 600, whiteSpace: "nowrap", transition: "all 0.2s"
        }}>{copied ? "✓ copied" : "copy"}</button>
      </div>
    </div>
  );
}

function PhaseTab({ phase, active, done, onClick }) {
  const icons = { encrypt: "🔐", transfer: "📡", decrypt: "🔓" };
  return (
    <button onClick={onClick} style={{
      flex: 1, padding: "14px 8px", border: "none", cursor: "pointer",
      background: active ? "rgba(0,245,212,0.08)" : "transparent",
      borderBottom: active ? "2px solid #00f5d4" : "2px solid transparent",
      color: active ? "#00f5d4" : done ? "#4ade80" : "#475569",
      fontWeight: 700, fontSize: 13, transition: "all 0.2s", letterSpacing: 0.5
    }}>
      {icons[phase]} {phase.toUpperCase()} {done && !active && "✓"}
    </button>
  );
}

export default function App() {
  const [phase, setPhase] = useState("encrypt");
  const [done, setDone] = useState({});
  const { key, nonce, encryptedBlob, originalName, encryptFile, decryptFile } = useFileEncryption();

  // Encrypt state
  const [encFile, setEncFile] = useState(null);
  const [encLogs, setEncLogs] = useState([]);
  const [encBusy, setEncBusy] = useState(false);
  const [localKey, setLocalKey] = useState("");
  const [localNonce, setLocalNonce] = useState("");
  const [localEncBlob, setLocalEncBlob] = useState(null);
  const [localOrigName, setLocalOrigName] = useState("");

  // Transfer state
  const [txLogs, setTxLogs] = useState([]);

  // Decrypt state
  const [decFile, setDecFile] = useState(null);
  const [decKey, setDecKey] = useState("");
  const [decNonce, setDecNonce] = useState("");
  const [decLogs, setDecLogs] = useState([]);
  const [decBusy, setDecBusy] = useState(false);
  const [decBlob, setDecBlob] = useState(null);
  const [decName, setDecName] = useState("");

  const log = (setter) => (msg) => setter(p => [...p, msg]);

  async function handleEncrypt() {
    if (!encFile) return;
    setEncBusy(true);
    setEncLogs([]);
    const addLog = log(setEncLogs);
    try {
      addLog(`> Loading file: ${encFile.name} (${(encFile.size / 1024).toFixed(1)} KB)`);
      addLog("> Generating AES-256-GCM key...");
      await new Promise(r => setTimeout(r, 400));
      addLog("> Generating random 96-bit nonce...");
      await new Promise(r => setTimeout(r, 300));
      const { keyB64, nonceB64 } = await encryptFile(encFile);
      setLocalKey(keyB64);
      setLocalNonce(nonceB64);
      setLocalEncBlob(encryptedBlob ?? null); // will be set after re-render
      setLocalOrigName(encFile.name);
      addLog("> Encrypting with AES-256-GCM...");
      await new Promise(r => setTimeout(r, 400));
      addLog("✅ Encryption successful!");
      addLog(`> Key: ${keyB64.slice(0, 20)}...`);
      addLog(`> Nonce: ${nonceB64}`);
      setDone(d => ({ ...d, encrypt: true }));
    } catch (e) {
      log(setEncLogs)(`❌ Error: ${e.message}`);
    }
    setEncBusy(false);
  }

  // We need to use the blob from the hook after state update
  const encryptedBlobRef = useRef(null);
  const keyRef = useRef("");
  const nonceRef = useRef("");

  async function handleEncryptFull() {
    if (!encFile) return;
    setEncBusy(true);
    setEncLogs([]);
    const addLog = (m) => setEncLogs(p => [...p, m]);
    try {
      addLog(`> Loading: ${encFile.name} (${(encFile.size / 1024).toFixed(1)} KB)`);
      addLog("> Generating AES-256-GCM key (256-bit)...");
      const cryptoKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      addLog("> Generating 96-bit random nonce...");
      const buffer = await encFile.arrayBuffer();
      addLog("> Encrypting payload...");
      await new Promise(r => setTimeout(r, 300));
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, buffer);
      const rawKey = await crypto.subtle.exportKey("raw", cryptoKey);
      const kb = btoa(String.fromCharCode(...new Uint8Array(rawKey)));
      const nb = btoa(String.fromCharCode(...iv));
      keyRef.current = kb;
      nonceRef.current = nb;
      encryptedBlobRef.current = new Blob([encrypted]);
      setLocalKey(kb);
      setLocalNonce(nb);
      setLocalEncBlob(new Blob([encrypted]));
      setLocalOrigName(encFile.name);
      addLog("✅ Encryption complete!");
      addLog(`> Algorithm: AES-256-GCM`);
      addLog(`> Encrypted size: ${(encrypted.byteLength / 1024).toFixed(1)} KB`);
      setDone(d => ({ ...d, encrypt: true }));
    } catch (e) { addLog(`❌ ${e.message}`); }
    setEncBusy(false);
  }

  function downloadEncrypted() {
    if (!localEncBlob) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(localEncBlob);
    a.download = localOrigName + ".enc";
    a.click();
  }

  function simulateTransfer() {
    setTxLogs([]);
    const msgs = [
      "> Initializing TCP socket...",
      "> Binding to port 9000...",
      "> Sending metadata (JSON): { nonce, filename, size }",
      "> Transmitting encrypted payload...",
      "> [████████████████] 100% — transfer complete",
      "✅ File received successfully on target device!",
    ];
    msgs.forEach((m, i) => setTimeout(() => setTxLogs(p => [...p, m]), i * 500));
    setTimeout(() => setDone(d => ({ ...d, transfer: true })), msgs.length * 500 + 200);
  }

  async function handleDecrypt() {
    if (!decFile || !decKey || !decNonce) return;
    setDecBusy(true);
    setDecLogs([]);
    const addLog = (m) => setDecLogs(p => [...p, m]);
    try {
      addLog(`> Loading encrypted file: ${decFile.name}`);
      addLog("> Importing AES-256-GCM key...");
      const keyBytes = Uint8Array.from(atob(decKey.trim()), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(decNonce.trim()), c => c.charCodeAt(0));
      const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
      addLog("> Verifying GCM authentication tag...");
      await new Promise(r => setTimeout(r, 400));
      const buffer = await decFile.arrayBuffer();
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, buffer);
      addLog("✅ Authentication tag verified — no tampering detected!");
      addLog("> Decrypting payload...");
      await new Promise(r => setTimeout(r, 200));
      const blob = new Blob([decrypted]);
      const origName = decFile.name.replace(/\.enc$/, "");
      setDecBlob(blob);
      setDecName("decrypted_" + origName);
      addLog(`✅ Decryption successful! (${(blob.size / 1024).toFixed(1)} KB)`);
      setDone(d => ({ ...d, decrypt: true }));
    } catch (e) {
      addLog(`❌ Decryption failed: ${e.message}`);
      addLog("   Check your key and nonce are correct.");
    }
    setDecBusy(false);
  }

  function downloadDecrypted() {
    if (!decBlob) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(decBlob);
    a.download = decName;
    a.click();
  }

  const inputStyle = {
    width: "100%", background: "#0f172a", border: "1px solid #1e293b",
    borderRadius: 8, padding: "10px 12px", color: "#e2e8f0",
    fontFamily: "monospace", fontSize: 12, outline: "none", boxSizing: "border-box"
  };

  const btnStyle = (active, color = "#00f5d4") => ({
    padding: "12px 24px", background: active ? color : "#1e293b",
    color: active ? "#0f172a" : "#64748b", border: "none", borderRadius: 10,
    fontWeight: 700, fontSize: 13, cursor: active ? "pointer" : "not-allowed",
    transition: "all 0.2s", letterSpacing: 0.5
  });

  return (
    <div style={{
      minHeight: "100vh", background: "#0a0f1e",
      backgroundImage: "radial-gradient(ellipse at 20% 50%, rgba(0,245,212,0.04) 0%, transparent 60%), radial-gradient(ellipse at 80% 20%, rgba(59,130,246,0.05) 0%, transparent 50%)",
      fontFamily: "'Segoe UI', system-ui, sans-serif", padding: "32px 16px",
      color: "#e2e8f0"
    }}>
      <div style={{ maxWidth: 680, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div style={{ fontSize: 11, letterSpacing: 4, color: "#00f5d4", textTransform: "uppercase", marginBottom: 12 }}>
            FED Entrepreneurship Program
          </div>
          <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800, color: "#f1f5f9", letterSpacing: -0.5 }}>
            🔐 Secure File Transfer
          </h1>
          <p style={{ margin: "10px 0 0", color: "#64748b", fontSize: 14 }}>
            AES-256-GCM Encryption · TCP/IP Transfer · Integrity Verified
          </p>
        </div>

        {/* Phase tabs */}
        <div style={{
          display: "flex", background: "#0f172a", borderRadius: 14,
          border: "1px solid #1e293b", overflow: "hidden", marginBottom: 24
        }}>
          {PHASES.map(p => (
            <PhaseTab key={p} phase={p} active={phase === p} done={done[p]} onClick={() => setPhase(p)} />
          ))}
        </div>

        {/* Panel */}
        <div style={{
          background: "#0f172a", borderRadius: 16, border: "1px solid #1e293b",
          padding: 28, boxShadow: "0 25px 50px rgba(0,0,0,0.5)"
        }}>

          {/* ENCRYPT */}
          {phase === "encrypt" && (
            <div>
              <h2 style={{ margin: "0 0 6px", fontSize: 18, color: "#f1f5f9" }}>🔐 Encrypt Your File</h2>
              <p style={{ margin: "0 0 20px", color: "#64748b", fontSize: 13 }}>
                Select any file. It will be encrypted using AES-256-GCM in your browser — your file never leaves this page.
              </p>
              <DropZone label="Drop any file to encrypt" onFile={setEncFile} />
              {encFile && (
                <div style={{ marginTop: 12, padding: "10px 14px", background: "#020617", borderRadius: 8, fontSize: 13, color: "#7dd3fc" }}>
                  📄 {encFile.name} — {(encFile.size / 1024).toFixed(1)} KB
                </div>
              )}
              <div style={{ marginTop: 20 }}>
                <StatusLog logs={encLogs} />
              </div>
              {localKey && (
                <div style={{ marginTop: 16, padding: 16, background: "#020617", borderRadius: 10, border: "1px solid #1e3a2f" }}>
                  <div style={{ fontSize: 12, color: "#4ade80", fontWeight: 700, marginBottom: 8 }}>
                    🔑 Encryption Keys — Share these with the receiver
                  </div>
                  <KeyBadge label="AES-256 Key (Base64)" value={localKey} />
                  <KeyBadge label="Nonce / IV (Base64)" value={localNonce} />
                </div>
              )}
              <div style={{ display: "flex", gap: 12, marginTop: 20 }}>
                <button
                  onClick={handleEncryptFull}
                  disabled={!encFile || encBusy}
                  style={btnStyle(!!encFile && !encBusy)}
                >
                  {encBusy ? "Encrypting…" : "Encrypt File"}
                </button>
                {localEncBlob && (
                  <button onClick={downloadEncrypted} style={btnStyle(true, "#3b82f6")}>
                    ⬇ Download .enc
                  </button>
                )}
              </div>
            </div>
          )}

          {/* TRANSFER */}
          {phase === "transfer" && (
            <div>
              <h2 style={{ margin: "0 0 6px", fontSize: 18, color: "#f1f5f9" }}>📡 Transfer Over IP</h2>
              <p style={{ margin: "0 0 20px", color: "#64748b", fontSize: 13 }}>
                In the CLI version, sender.py opens a TCP socket and streams the encrypted file to receiver.py on the target device.
                The demo below simulates this handshake.
              </p>
              <div style={{ background: "#020617", borderRadius: 10, padding: 16, marginBottom: 20, fontFamily: "monospace", fontSize: 12 }}>
                <div style={{ color: "#64748b", marginBottom: 10 }}>— Sender device —</div>
                <div style={{ color: "#4ade80" }}>$ python receiver.py --port 9000 --password mysecret</div>
                <div style={{ color: "#64748b", margin: "10px 0" }}>— Receiver device (run first) —</div>
                <div style={{ color: "#4ade80" }}>$ python sender.py --file secret.txt --host 192.168.x.x --port 9000 --password mysecret</div>
              </div>
              <div style={{ display: "flex", gap: 16, marginBottom: 20 }}>
                {[["Sender IP", "192.168.1.5"], ["Receiver IP", "192.168.1.10"], ["Port", "9000"]].map(([l, v]) => (
                  <div key={l} style={{ flex: 1, background: "#020617", borderRadius: 8, padding: "12px 14px", border: "1px solid #1e293b" }}>
                    <div style={{ fontSize: 10, color: "#475569", textTransform: "uppercase", letterSpacing: 1 }}>{l}</div>
                    <div style={{ fontFamily: "monospace", color: "#7dd3fc", fontSize: 13, marginTop: 4 }}>{v}</div>
                  </div>
                ))}
              </div>
              <StatusLog logs={txLogs} />
              <button onClick={simulateTransfer} style={{ ...btnStyle(true), marginTop: 20 }}>
                Simulate Transfer
              </button>
            </div>
          )}

          {/* DECRYPT */}
          {phase === "decrypt" && (
            <div>
              <h2 style={{ margin: "0 0 6px", fontSize: 18, color: "#f1f5f9" }}>🔓 Decrypt the File</h2>
              <p style={{ margin: "0 0 20px", color: "#64748b", fontSize: 13 }}>
                Upload the .enc file and paste the key + nonce from the encryption step to recover the original file.
              </p>
              <DropZone label="Drop the .enc file here" onFile={setDecFile} accept=".enc,*" />
              {decFile && (
                <div style={{ marginTop: 10, padding: "10px 14px", background: "#020617", borderRadius: 8, fontSize: 13, color: "#7dd3fc" }}>
                  🔒 {decFile.name} — {(decFile.size / 1024).toFixed(1)} KB
                </div>
              )}
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 12, color: "#64748b", marginBottom: 6 }}>AES-256 Key (Base64)</div>
                <input style={inputStyle} placeholder="Paste key here…" value={decKey} onChange={e => setDecKey(e.target.value)} />
              </div>
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 12, color: "#64748b", marginBottom: 6 }}>Nonce / IV (Base64)</div>
                <input style={inputStyle} placeholder="Paste nonce here…" value={decNonce} onChange={e => setDecNonce(e.target.value)} />
              </div>
              <div style={{ marginTop: 20 }}>
                <StatusLog logs={decLogs} />
              </div>
              <div style={{ display: "flex", gap: 12, marginTop: 20 }}>
                <button
                  onClick={handleDecrypt}
                  disabled={!decFile || !decKey || !decNonce || decBusy}
                  style={btnStyle(!!decFile && !!decKey && !!decNonce && !decBusy)}
                >
                  {decBusy ? "Decrypting…" : "Decrypt File"}
                </button>
                {decBlob && (
                  <button onClick={downloadDecrypted} style={btnStyle(true, "#4ade80")}>
                    ⬇ Download Decrypted
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Progress bar */}
        <div style={{ display: "flex", gap: 8, marginTop: 24, alignItems: "center" }}>
          {PHASES.map((p, i) => (
            <div key={p} style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
              <div style={{
                flex: 1, height: 4, borderRadius: 4,
                background: done[p] ? "#00f5d4" : phase === p ? "rgba(0,245,212,0.3)" : "#1e293b",
                transition: "all 0.4s"
              }} />
              {i < PHASES.length - 1 && <div style={{ width: 6, height: 6, borderRadius: "50%", background: done[p] ? "#00f5d4" : "#1e293b" }} />}
            </div>
          ))}
        </div>
        <div style={{ textAlign: "center", marginTop: 20, fontSize: 11, color: "#334155" }}>
          All encryption runs locally in your browser · WebCrypto API · AES-256-GCM
        </div>
      </div>
    </div>
  );
}
