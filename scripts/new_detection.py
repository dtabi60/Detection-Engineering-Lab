from pathlib import Path


def slugify(text):
    return text.lower().replace(" ", "_").replace("-", "_")


def main():
    title = input("Detection title: ")
    technique_id = input("MITRE technique ID: ")
    technique_name = input("MITRE technique name: ")
    tactic = input("MITRE tactic: ")
    description = input("Description: ")

    patterns = []

    while True:
        value = input("Pattern value (or press Enter to finish): ")

        if value == "":
            break

        score = input("Score for this pattern: ")

        patterns.append((value, score))

    rule_name = slugify(title)

    detection_path = Path("detections") / f"{rule_name}.yaml"
    docs_path = Path("docs") / f"{rule_name}.md"
    sample_log_path = Path("sample_logs") / f"{rule_name}_test.txt"

    yaml_content = f'title: "{title}"\n'
    yaml_content += f'id: "{rule_name}-001"\n'
    yaml_content += f'description: "{description}"\n\n'
    yaml_content += "mitre:\n"
    yaml_content += f'  technique_id: "{technique_id}"\n'
    yaml_content += f'  technique_name: "{technique_name}"\n'
    yaml_content += f'  tactic: "{tactic}"\n\n'
    yaml_content += "patterns:\n"

    for value, score in patterns:
        yaml_content += f'  - value: "{value}"\n'
        yaml_content += f"    score: {score}\n"

    yaml_content += '\nfalse_positives:\n'
    yaml_content += '  - "Administrative activity"\n'
    yaml_content += '  - "Security testing"\n\n'
    yaml_content += 'level: "medium"\n'

    docs_content = f"# {title}\n\n"
    docs_content += "## Overview\n\n"
    docs_content += f"{description}\n\n"
    docs_content += "## MITRE ATT&CK Mapping\n\n"
    docs_content += f"- Technique: {technique_id}\n"
    docs_content += f"- Name: {technique_name}\n"
    docs_content += f"- Tactic: {tactic}\n\n"
    docs_content += "## Detection Logic\n\n"
    for value, score in patterns:
        docs_content += f"- `{value}` — Score: {score}\n"

    docs_content += "\n## False Positives\n\n"
    docs_content += "- Administrative activity\n"
    docs_content += "- Security testing\n"

    sample_content = "CommandLine=" + " ".join([value for value, score in patterns])

    detection_path.write_text(yaml_content)
    docs_path.write_text(docs_content)
    sample_log_path.write_text(sample_content)

    print("Created:")
    print(detection_path)
    print(docs_path)
    print(sample_log_path)


if __name__ == "__main__":
    main()