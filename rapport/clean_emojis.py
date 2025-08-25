#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

def clean_emojis(content):
    """Remove emojis and special Unicode characters"""
    replacements = {
        '⚠️': '[WARNING]',
        '🔐': '[SECURE]',
        '⏰': '[TIME]',
        '🏥': '[HOSPITAL]'
    }
    
    for emoji, replacement in replacements.items():
        content = content.replace(emoji, replacement)
    
    return content

# Clean emojis from chapitre4_tests.tex
file_path = 'sections/chapitre4_tests.tex'
try:
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Clean emojis
    cleaned_content = clean_emojis(content)

    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(cleaned_content)

    print(f"Emojis cleaned from {file_path}")
except Exception as e:
    print(f"Error processing {file_path}: {e}")

print("Emoji cleaning complete!")
