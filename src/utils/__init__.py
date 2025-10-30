"""
Pacote utils - Funções auxiliares para o Web Security Scanner
"""

from .helpers import (
    Colors,
    print_banner,
    validate_url,
    is_valid_http_url,
    clean_url,
    extract_domain,
    is_same_domain,
    print_success,
    print_error,
    print_info,
    print_warning,
    sanitize_filename,
    get_severity_color,
    format_vulnerability_output,
    get_user_agent,
    truncate_string
)

__all__ = [
    'Colors',
    'print_banner',
    'validate_url',
    'is_valid_http_url',
    'clean_url',
    'extract_domain',
    'is_same_domain',
    'print_success',
    'print_error',
    'print_info',
    'print_warning',
    'sanitize_filename',
    'get_severity_color',
    'format_vulnerability_output',
    'get_user_agent',
    'truncate_string'
]