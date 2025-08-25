#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

# Read the file
with open('sections/chapitre3_implementation.tex', 'r', encoding='utf-8') as f:
    content = f.read()

# Clean accented characters
cleaned_content = clean_utf8_chars(content)

# Write back
with open('sections/chapitre3_implementation.tex', 'w', encoding='utf-8') as f:
    f.write(cleaned_content)

print("UTF-8 characters cleaned from chapitre3_implementation.tex")
