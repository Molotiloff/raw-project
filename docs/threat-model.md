# Исходная модель угроз

## Активы

- данные пользователей;
- события авторизации;
- операции;
- токены/учётные данные;
- WebSocket-сессии;
- подписки;
- журналы аудита;
- доступность шлюза и БД.

## Доверительные границы

1. Клиент <-> публичная/недоверенная сеть.
2. Сеть <-> WebSocket gateway.
3. Gateway <-> backend/database.
4. Административный контур.

## Приоритетные сценарии

| ID | Сценарий | Риск | Планируемая защита |
|---|---|---|---|
| T1 | Подключение неавторизованного WS-клиента | Утечка/доступ | mTLS + auth |
| T2 | Подписка на чужой объект (IDOR) | Нарушение конфиденциальности | object-level ACL |
| T3 | Replay/повтор токена или команды | Несанкционированные действия | TTL/session/nonce где применимо |
| T4 | Connection flood | DoS | rate limit + connection caps |
| T5 | Subscription flood | CPU/RAM exhaustion | subscription caps |
| T6 | Message flood | CPU/DB exhaustion | per-client rate limit |
| T7 | Oversized message | RAM/CPU exhaustion | max message size |
| T8 | Idle connection exhaustion | исчерпание соединений | ping/pong + timeout |
| T9 | Slow consumer/backpressure | рост буферов | bounded queues/disconnect policy |
| T10 | Malformed input | ошибки/аварии | schema validation |
| T11 | Information disclosure | раскрытие внутренней архитектуры | safe error responses |
| T12 | CSWSH при cookie auth | захват сессии | Origin validation + CSRF model |

## Основной набор для защиты

Для итоговой демонстрации достаточно выбрать 6–8 сценариев, которые можно стабильно воспроизводить и измерять.

Рекомендуемый набор:

- T1;
- T2;
- T4;
- T5;
- T6;
- T7;
- T8;
- T11.

## Формат эксперимента

Для каждого сценария фиксировать:

- начальные условия;
- конфигурацию сервера;
- шаги воспроизведения на собственном стенде;
- наблюдаемые метрики;
- влияние;
- механизм защиты;
- повторный результат.
