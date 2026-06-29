# TODO — что не реализовано в MVP (locrest-server)

1. **Raw TCP proxy** — путь `/3000/3000` сейчас отдаёт скрипт вместо открытия raw TCP-туннеля. Нужен отдельный handler, который проксирует TCP-соединение напрямую в `yamux`-туннель без HTTP-обёртки.

2. **CertMagic / On-Demand TLS / Wildcard DNS-01** — в `locrest.yaml` уже есть конфигурация `wildcard` и `on_demand`, но в коде (`tls.go`) реализованы только BYO-сертификат и базовый `autocert`. Нужно:
   - Интегрировать `caddyserver/certmagic` для wildcard DNS-01 с настраиваемым `libdns`-провайдером.
   - Реализовать `DecisionFunc` для On-Demand HTTP-01, который выдаёт сертификат только если домен/поддомен привязан к активному туннелю.

3. **BoltDB (`go.etcd.io/bbolt`) для persistent storage** — сейчас всё in-memory (`sync.Map` в auth store и routing table). Нужно добавить embedded storage для:
   - **Premium tokens** — bucket `tokens`, key=token string, value=subscription tier + expiry + owner.
   - **CNAME mappings** — bucket `cnames`, key=custom domain, value=subdomain + owner_id.

4. **Graceful cleanup при disconnect клиента** — `chiselwrapper.DeleteUser` и `Frontend.UnregisterRoute` существуют, но не вызываются при обрыве соединения. Нужен callback/hook на disconnect от Chisel, чтобы мгновенно чистить пользователя и маршрут из routing table.

5. **Session TTL tracking** — `TTL` is a single hard limit; sessions expire unconditionally after this duration.

6. **Embedbin binaries** — бинарники клиента (`locrest-client-*`) лежат в `internal/embedbin/bin/`, но директория не попадает в git (`.gitignore`). Нужен CI/CD или `make` target для сборки и встраивания бинарей.
