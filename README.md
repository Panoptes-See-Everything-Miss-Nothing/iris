# Iris
Pulls data from various to write into JSON file


# Pre-requisites
1. Python3 and pip installed
2. Install python3.13 system wide with venv support
    ```bash
    sudo apt update
    sudo apt install python3.13 python3.13-venv
    ```
3. Install direnv
    ```bash
    sudo apt install direnv
    ```

4. Configure direnv in you shell:
    - For bash, add to ~/.bashrc eval
    ```bash
    "eval $(direnv hook bash)"
    ```
    - For zsh, add to ~/.zshrc
    ```bash
    "eva $(direnv hook zsh)"
    ```

    Then reload shell configuration
    ```bash
    source ~/.bashrc
    ```
5. Run direnv in the project folder
    ```bash "direnv allow"```


# Recommended/Optional
1. Install black system wide
    ```bash
    sudo apt update
    sudo apt install black
    ```
