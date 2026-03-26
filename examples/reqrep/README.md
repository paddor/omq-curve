# Encrypted REQ/REP Example

```sh
# Terminal 1 — start server
ruby server.rb

# Server listening on tcp://0.0.0.0:5555 (CURVE encrypted)
#
#   Start client with:
#   SERVER_KEY=gh8RuBEo2em%P$)v)Jmo{n?#Dc.nPnQ}OK2?nli$ ruby client.rb
```

```sh
# Terminal 2 — copy the command from above
SERVER_KEY=gh8RuBEo2em%P$)v)Jmo{n?#Dc.nPnQ}OK2?nli$ ruby client.rb
```

## Custom endpoint

```sh
ruby server.rb tcp://*:9000
SERVER_KEY=... ruby client.rb tcp://otherhost:9000
```

## Persistent keys

```sh
omq-keygen server
# server_public=rq5+eJ...
# server_secret=x8Kn2P...

SERVER_PUBLIC=rq5+eJ... SERVER_SECRET=x8Kn2P... ruby server.rb
```
