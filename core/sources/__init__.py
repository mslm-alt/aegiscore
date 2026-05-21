"""
core/sources/
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Source Adapter Interface.

Şu an desteklenen kaynaklar main.py içinde doğrudan yönetilir.
Bu modül yalnız ortak adapter sözleşmesini dışa açar.

Yeni kaynak eklemek için:
  1. BaseSourceAdapter'ı subclass et
"""
from .base import BaseSourceAdapter

__all__ = ["BaseSourceAdapter"]
