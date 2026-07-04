"""
detector.py

Detection logic for suspicious PowerShell activity.
"""


class Detector:

    def __init__(self):

        self.suspicious_flags = [
            "-ExecutionPolicy Bypass",
            "-NoProfile",
            "-EncodedCommand",
            "-enc",
            "-WindowStyle Hidden",
            "-nop"
        ]

    def detect(self, log_text):

        findings = []

        for flag in self.suspicious_flags:

            if flag.lower() in log_text.lower():

                findings.append(flag)

        return findings


if __name__ == "__main__":

    sample_log = """
    Image=powershell.exe
    CommandLine=powershell.exe -NoProfile -ExecutionPolicy Bypass
    """

    detector = Detector()

    results = detector.detect(sample_log)

    print("===== Detection Results =====")

    if results:

        for result in results:

            print(f"Suspicious flag detected: {result}")

    else:

        print("No suspicious behavior found.")