"use client";

import { useState } from "react";

type EventItem = {
  event: string;
  data: string;
};

export default function Page() {
  const [apiKey, setApiKey] = useState("");
  const [gateway, setGateway] = useState("http://127.0.0.1:8080");
  const [mode, setMode] = useState("office");
  const [message, setMessage] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [events, setEvents] = useState<EventItem[]>([]);

  async function send() {
    setEvents([]);
    const response = await fetch(`${gateway}/api/chat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Khaos-Key": apiKey,
      },
      body: JSON.stringify({ session_id: sessionId, mode, message }),
    });
    const payload = await response.json();
    setSessionId(payload.session_id);
    const keyParam = apiKey ? `?key=${encodeURIComponent(apiKey)}` : "";
    const source = new EventSource(`${gateway}/api/chat/${payload.session_id}/stream${keyParam}`);
    for (const eventName of ["message", "tool_call", "tool_result", "permission_request", "error", "done"]) {
      source.addEventListener(eventName, (event) => {
        setEvents((prev) => [...prev, { event: eventName, data: (event as MessageEvent).data }]);
        if (eventName === "done" || eventName === "error") {
          source.close();
        }
      });
    }
  }

  async function confirm(id: string, approved: boolean) {
    if (!sessionId) return;
    await fetch(`${gateway}/api/chat/${sessionId}/confirm`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Khaos-Key": apiKey,
      },
      body: JSON.stringify({ tool_call_id: id, approved, remember: false }),
    });
  }

  return (
    <main className="shell">
      <section className="toolbar">
        <strong>Khaos</strong>
        <select value={mode} onChange={(event) => setMode(event.target.value)}>
          <option value="office">Office</option>
          <option value="coding">Coding</option>
        </select>
        <input value={gateway} onChange={(event) => setGateway(event.target.value)} />
        <input placeholder="X-Khaos-Key" value={apiKey} onChange={(event) => setApiKey(event.target.value)} />
      </section>
      <section className="conversation">
        {events.map((item, index) => (
          <article key={index} className={`event ${item.event}`}>
            <header>{item.event}</header>
            <pre>{item.data}</pre>
            {item.event === "permission_request" && (
              <footer>
                <button onClick={() => confirm(JSON.parse(item.data).id, true)}>Allow</button>
                <button onClick={() => confirm(JSON.parse(item.data).id, false)}>Deny</button>
              </footer>
            )}
          </article>
        ))}
      </section>
      <section className="composer">
        <textarea value={message} onChange={(event) => setMessage(event.target.value)} />
        <button onClick={send}>Send</button>
      </section>
    </main>
  );
}
