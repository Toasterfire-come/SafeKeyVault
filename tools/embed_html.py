#!/usr/bin/env python3

import os
import sys

def main():
    if len(sys.argv) != 3:
        print("Usage: embed_html.py <input_html> <output_header>")
        sys.exit(1)

    input_html = sys.argv[1]
    output_header = sys.argv[2]

    # Read the HTML file
    with open(input_html, 'rb') as f:
        html_content = f.read()

    # Generate the C header content
    header_content = f"""#ifndef COMPANION_HTML_H
#define COMPANION_HTML_H

#include <stdint.h>
#include <stddef.h>

const uint8_t k_companion_html[] = {{
{', '.join(f'0x{b:02x}' for b in html_content)}
}};

const size_t k_companion_html_len = {len(html_content)};

#endif // COMPANION_HTML_H
"""

    # Write the header file
    with open(output_header, 'w') as f:
        f.write(header_content)

    print(f"Generated {output_header} from {input_html}")

if __name__ == '__main__':
    main()
