# Community Rule Pack

Bu klasöre topluluk tarafından yazılan kurallar eklenir.

## Kural yazma kuralları

1. Her kural dosyasının başında pack, version, author bilgisi olmalı
2. Her kural için mitre_tactic ve mitre_technique zorunlu
3. ID formatı: COM-{KISA_AD}-{NUMARA} (örn: COM-WEB-001)
4. Yeni kural eklemeden önce: `python3 main.py --validate-rules`

## Örnek kural

```yaml
- id: COM-WEB-001
  name: Suspicious Admin Path Access
  severity: high
  score: 80
  category: web
  message: "Şüpheli admin path erişimi"
  mitre_tactic: TA0001
  mitre_technique: T1190
  tags: [web, initial-access]
  pack: community
  pack_version: "1.0"
  condition:
    source: [apache2, nginx]
    action: http_request
    fields:
      path_contains: /admin
```
