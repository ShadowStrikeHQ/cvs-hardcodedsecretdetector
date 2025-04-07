#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys
import entropy

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Regular expressions for common secrets
PATTERNS = {
    "API Key": r"[A-Za-z0-9]{32,45}",  # Example pattern, adjust as needed
    "Password": r"(password|pwd|secret)\s*[:=]\s*['\"]?([^'\"]+)['\"]?",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"[\w+=/]{40}",
    "SQL Connection String": r"Server=.*?Database=.*?User Id=.*?Password=.*?",
    "Database Credentials": r"jdbc:.*?://.*?:.*?",  # Broad JDBC pattern for initial detection
}


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans source code for hardcoded secrets.")
    parser.add_argument("path", help="Path to the file or directory to scan.")
    parser.add_argument("-e", "--entropy", action="store_true", help="Enable entropy analysis for additional checks.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Path to output file to save results.", default=None)
    return parser.parse_args()


def scan_file(file_path, enable_entropy=False, output_file=None):
    """
    Scans a single file for hardcoded secrets.

    Args:
        file_path (str): The path to the file to scan.
        enable_entropy (bool): Whether to enable entropy analysis.
        output_file (str): Path to the output file to save results.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return

    found_secrets = []

    for name, pattern in PATTERNS.items():
        matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            secret = match.group(0)
            line_number = content[:match.start()].count('\n') + 1
            context = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
            found_secrets.append(
                f"File: {file_path}, Line: {line_number}, Type: {name}, Secret: {secret}, Context: {context}"
            )
            logging.warning(f"Potential secret found in {file_path} (Line {line_number}): {name}")

    if enable_entropy:
        high_entropy_strings = find_high_entropy_strings(content)
        for string, position in high_entropy_strings:
            line_number = content[:position].count('\n') + 1
            context = content[max(0, position - 50):min(len(content), position + len(string) + 50)]
            found_secrets.append(
                f"File: {file_path}, Line: {line_number}, Type: High Entropy String, Secret: {string}, Context: {context}"
            )
            logging.warning(f"Potential high entropy string found in {file_path} (Line {line_number}): {string}")

    if output_file:
        try:
            with open(output_file, "a") as outfile:
                for secret_info in found_secrets:
                    outfile.write(secret_info + "\n")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")

    return found_secrets


def find_high_entropy_strings(text, min_length=16, threshold=3.5):
    """
    Finds high entropy strings within the given text.

    Args:
        text (str): The text to analyze.
        min_length (int): Minimum length of the string to consider.
        threshold (float): Entropy threshold above which a string is considered high entropy.

    Returns:
        list: A list of tuples containing the high entropy string and its starting position.
    """
    high_entropy_strings = []
    for i in range(len(text) - min_length + 1):
        substring = text[i:i + min_length]
        entropy_value = entropy.shannon_entropy(substring.encode('utf-8'))
        if entropy_value > threshold:
            high_entropy_strings.append((substring, i))
    return high_entropy_strings


def scan_directory(dir_path, enable_entropy=False, output_file=None):
    """
    Recursively scans a directory for hardcoded secrets.

    Args:
        dir_path (str): The path to the directory to scan.
        enable_entropy (bool): Whether to enable entropy analysis.
        output_file (str): Path to the output file to save results.
    """
    all_secrets = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            secrets = scan_file(file_path, enable_entropy, output_file)
            if secrets:
                all_secrets.extend(secrets)
    return all_secrets


def validate_input(path):
    """
    Validates the input path.

    Args:
        path (str): The path to validate.

    Returns:
        bool: True if the path is valid, False otherwise.
    """
    if not os.path.exists(path):
        logging.error(f"Path does not exist: {path}")
        return False
    return True


def main():
    """
    Main function to run the hardcoded secret detector.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    if not validate_input(args.path):
        sys.exit(1)

    if os.path.isfile(args.path):
        secrets = scan_file(args.path, args.entropy, args.output)
        if secrets:
            print("\n".join(secrets))  # Print results to console
    elif os.path.isdir(args.path):
        secrets = scan_directory(args.path, args.entropy, args.output)
        if secrets:
            print("\n".join(secrets)) # Print results to console
    else:
        logging.error(f"Invalid path type: {args.path}")
        sys.exit(1)

    if not secrets and not args.output:
        print("No secrets found.")


if __name__ == "__main__":
    main()