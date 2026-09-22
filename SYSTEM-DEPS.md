# System dependencies (Debian/Ubuntu)

    sudo apt-get install -y p7zip-full unrar clamav
    sudo freshclam            # update ClamAV signatures
    # optional, for tier 2/3:
    sudo apt-get install -y yara osslsigncode radare2 innoextract

The tool also self-provisions these on first run (`triage-bro --setup`).
