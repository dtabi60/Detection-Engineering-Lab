import streamlit as st


SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "mshta",
    "mimikatz",
    "encodedcommand",
]


def render_process_tree(process_tree):
    st.subheader("🌳 Interactive Process Tree")

    if not process_tree:
        st.info("No process tree available.")
        return

    tree_data = process_tree.get("process_tree", process_tree)

    if not isinstance(tree_data, dict):
        st.json(tree_data)
        return

    root_name = tree_data.get("process_name", "Unknown")
    children = tree_data.get("children", [])

    col1, col2, col3 = st.columns(3)

    col1.metric("Root Process", root_name)
    col2.metric("Child Processes", len(children))
    col3.metric("Risk", calculate_tree_risk(tree_data))

    st.divider()

    render_node(tree_data, depth=0)

    st.divider()

    with st.expander("Raw Process Tree JSON"):
        st.json(process_tree)


def render_node(node, depth=0):
    process_name = node.get("process_name", "unknown_process")
    pid = node.get("process_id", node.get("pid", "unknown_pid"))
    command_line = node.get("command_line", "")
    user = node.get("user", "Unknown")
    children = node.get("children", [])

    risk_label = get_process_risk(process_name, command_line)
    icon = get_process_icon(process_name)

    indent = " " * depth

    title = f"{indent}{icon} {process_name} | PID: {pid} | Risk: {risk_label}"

    expanded = depth == 0 or risk_label in ["High", "Medium"]

    with st.expander(title, expanded=expanded):
        c1, c2, c3 = st.columns(3)

        c1.write(f"**Process:** `{process_name}`")
        c2.write(f"**PID:** `{pid}`")
        c3.write(f"**User:** `{user}`")

        st.write("**Command Line:**")
        st.code(command_line or "No command line available.", language="powershell")

        if risk_label == "High":
            st.error("High-risk process behavior detected.")
        elif risk_label == "Medium":
            st.warning("Suspicious process behavior observed.")
        else:
            st.success("No obvious suspicious indicators found.")

        if children:
            st.write("**Child Processes:**")
            for child in children:
                render_node(child, depth + 1)


def get_process_risk(process_name, command_line):
    combined = f"{process_name} {command_line}".lower()

    if any(keyword in combined for keyword in ["mimikatz", "encodedcommand"]):
        return "High"

    if any(keyword in combined for keyword in SUSPICIOUS_KEYWORDS):
        return "Medium"

    return "Low"


def calculate_tree_risk(node):
    risks = []

    def walk(current):
        risks.append(
            get_process_risk(
                current.get("process_name", ""),
                current.get("command_line", ""),
            )
        )

        for child in current.get("children", []):
            walk(child)

    walk(node)

    if "High" in risks:
        return "High"

    if "Medium" in risks:
        return "Medium"

    return "Low"


def get_process_icon(process_name):
    name = str(process_name).lower()

    if "powershell" in name:
        return "🔵"
    if "cmd" in name:
        return "⚫"
    if "explorer" in name:
        return "🪟"
    if "chrome" in name or "edge" in name or "firefox" in name:
        return "🌐"
    if "python" in name:
        return "🐍"
    if "mimikatz" in name:
        return "🚨"
    if "rundll32" in name or "regsvr32" in name:
        return "🧩"
    if "certutil" in name:
        return "📜"

    return "⚙️"