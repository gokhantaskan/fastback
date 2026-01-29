#!/usr/bin/env python3
"""Compile email templates by inlining CSS and minifying HTML.

This script processes Jinja2 email templates, inlines their CSS, and minifies
the output. The compiled templates are saved to the compiled/ subdirectory.

Run this script after modifying email templates:
    make compile-emails

Or directly:
    python scripts/compile_emails.py
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import css_inline  # noqa: E402
import minify_html  # noqa: E402
from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402

# Template configuration: maps template names to their Jinja2 variables
TEMPLATES = {
    "password-reset.j2": ["reset_url"],
    "email-verification.j2": ["verification_url"],
    "email-change-verification.j2": ["new_email", "verification_url"],
}

# URL-safe marker that preserves quotes during minification
# Using a URL format ensures the minifier keeps quotes around href values
MARKER_URL_PREFIX = "https://jinja-placeholder.local/var/"


def compile_template(
    env: Environment,
    template_name: str,
    variables: list[str],
    output_dir: Path,
) -> None:
    """Compile a single email template.

    Args:
        env: Jinja2 environment
        template_name: Name of the template file
        variables: List of Jinja2 variable names used in the template
        output_dir: Directory to save compiled template
    """
    # Create placeholder context using URL-safe markers
    # This ensures minifier preserves quotes around attribute values
    context = {var: f"{MARKER_URL_PREFIX}{var}" for var in variables}

    # Render template with placeholders
    template = env.get_template(template_name)
    html_content = template.render(**context)

    # Inline CSS
    html_content = css_inline.inline(html_content)

    # Minify HTML
    html_content = minify_html.minify(html_content, minify_css=True)

    # Replace URL markers back to Jinja2 syntax
    # Handle both quoted and unquoted attribute values (minifier may strip quotes)
    for var in variables:
        marker = f"{MARKER_URL_PREFIX}{var}"
        jinja_var = f"{{{{ {var} }}}}"
        # Replace unquoted marker (e.g., href=marker) with quoted Jinja2 var
        html_content = html_content.replace(f"={marker}>", f'="{jinja_var}">')
        html_content = html_content.replace(f"={marker} ", f'="{jinja_var}" ')
        # Replace quoted marker
        html_content = html_content.replace(f'"{marker}"', f'"{jinja_var}"')
        # Replace any remaining occurrences (text content)
        html_content = html_content.replace(marker, jinja_var)

    # Save compiled template with .html extension
    output_name = Path(template_name).stem + ".html"
    output_path = output_dir / output_name
    output_path.write_text(html_content, encoding="utf-8")
    print(f"  ✓ {template_name} -> {output_name}")


def main() -> None:
    """Compile all email templates."""
    templates_dir = project_root / "app" / "templates" / "emails"
    output_dir = templates_dir / "compiled"

    # Create output directory
    output_dir.mkdir(exist_ok=True)

    # Setup Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )

    print("Compiling email templates...")

    for template_name, variables in TEMPLATES.items():
        template_path = templates_dir / template_name
        if not template_path.exists():
            print(f"  ✗ {template_name} (not found)")
            continue
        compile_template(env, template_name, variables, output_dir)

    print(f"\nCompiled templates saved to: {output_dir}")


if __name__ == "__main__":
    main()
