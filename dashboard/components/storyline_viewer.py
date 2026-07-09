import streamlit as st


def render_storyline_viewer(storyline):
    st.subheader("🧵 Storyline Timeline")

    if not storyline:
        st.info("No storyline available.")
        return

    events = extract_storyline_events(storyline)

    if not events:
        st.warning("Storyline returned data, but no events were found.")
        with st.expander("Raw Storyline JSON"):
            st.json(storyline)
        return

    c1, c2, c3 = st.columns(3)

    c1.metric("Storyline Events", len(events))
    c2.metric("First Event", events[0].get("timestamp", "Unknown"))
    c3.metric("Last Event", events[-1].get("timestamp", "Unknown"))

    st.divider()

    for event in events:
        render_storyline_event(event)

    st.divider()

    with st.expander("Raw Storyline JSON"):
        st.json(storyline)


def extract_storyline_events(storyline):
    if isinstance(storyline, dict):
        if isinstance(storyline.get("storyline"), list):
            return storyline["storyline"]

        if isinstance(storyline.get("events"), list):
            return storyline["events"]

        if isinstance(storyline.get("timeline"), list):
            return storyline["timeline"]

        if isinstance(storyline.get("storyline"), dict):
            nested = storyline["storyline"]
            if isinstance(nested.get("events"), list):
                return nested["events"]

    if isinstance(storyline, list):
        return storyline

    return []


def render_storyline_event(event):
    timestamp = event.get("timestamp", "Unknown time")
    event_type = event.get("event_type") or event.get("type") or "Event"
    process_name = event.get("process_name") or event.get("process") or "Unknown process"
    command_line = event.get("command_line") or event.get("cmdline") or ""
    severity = event.get("severity", "Unknown")

    title = f"{get_event_icon(event_type, process_name)} {timestamp} | {event_type} | {process_name}"

    with st.expander(title, expanded=is_suspicious_event(event)):
        c1, c2, c3 = st.columns(3)

        c1.write(f"**Type:** `{event_type}`")
        c2.write(f"**Process:** `{process_name}`")
        c3.write(f"**Severity:** `{severity}`")

        if command_line:
            st.write("**Command Line:**")
            st.code(command_line, language="powershell")

        st.write("**Event Details:**")
        st.json(event)


def is_suspicious_event(event):
    text = str(event).lower()

    suspicious_terms = [
        "powershell",
        "encodedcommand",
        "mimikatz",
        "certutil",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
        "mshta",
    ]

    return any(term in text for term in suspicious_terms)


def get_event_icon(event_type, process_name):
    text = f"{event_type} {process_name}".lower()

    if "powershell" in text:
        return "🔵"
    if "network" in text:
        return "🌐"
    if "file" in text:
        return "📁"
    if "registry" in text:
        return "🧬"
    if "process" in text:
        return "⚙️"
    if "alert" in text:
        return "🚨"

    return "•"