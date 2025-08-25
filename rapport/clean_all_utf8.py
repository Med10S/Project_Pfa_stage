#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re

def clean_utf8_chars(content):
    """Remove accented characters from content to avoid UTF-8 compilation issues"""
    replacements = {
        'à': 'a', 'â': 'a', 'ä': 'a',
        'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e',
        'î': 'i', 'ï': 'i',
        'ô': 'o', 'ö': 'o',
        'ù': 'u', 'û': 'u', 'ü': 'u',
        'ç': 'c',
        'À': 'A', 'Â': 'A', 'Ä': 'A',
        'È': 'E', 'É': 'E', 'Ê': 'E', 'Ë': 'E',
        'Î': 'I', 'Ï': 'I',
        'Ô': 'O', 'Ö': 'O',
        'Ù': 'U', 'Û': 'U', 'Ü': 'U',
        'Ç': 'C'
    }
    
    for accented, clean in replacements.items():
        content = content.replace(accented, clean)
    
    return content

# List of files to clean
tex_files = [
    'sections/chapitre1_contexte.tex',
    'sections/chapitre2_methodologie.tex',
    'sections/chapitre3_implementation.tex',
    'sections/chapitre4_tests.tex',
    'sections/remerciements.tex',
    'sections/resume.tex',
    'sections/abstract.tex',
    'sections/abreviations.tex',
    'annexes.tex'
]

for file_path in tex_files:
    if os.path.exists(file_path):
        try:
            # Read the file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Clean accented characters
            cleaned_content = clean_utf8_chars(content)

            # Write back
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(cleaned_content)

            print(f"UTF-8 characters cleaned from {file_path}")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    else:
        print(f"File not found: {file_path}")

print("All files processed!")
