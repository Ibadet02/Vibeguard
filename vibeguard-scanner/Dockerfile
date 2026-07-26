# VibeGuard hosted scanner.
# Node 22 (for native .env loading) + git (to clone repos). The AI reasoning pass
# talks to the provider over plain HTTPS, so there is nothing else to install.
#
# The optional claude-cli backend (VIBEGUARD_LLM_API=claude-cli) needs the Claude
# Code binary, which is deliberately NOT in this image: it would run
# --dangerously-skip-permissions against freshly cloned untrusted repos. If you
# want that backend, add `RUN npm install -g @anthropic-ai/claude-code` below and
# understand what you are turning on.

FROM node:22-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Run as non-root.
RUN useradd --create-home --uid 10001 app
ENV HOME=/home/app

WORKDIR /app
COPY . .
RUN chown -R app:app /app
USER app

ENV NODE_ENV=production
ENV VIBEGUARD_PUBLIC=1
ENV PORT=3488
EXPOSE 3488

# Provide these at RUNTIME in the host dashboard (never bake secrets into the image):
#   VIBEGUARD_LLM_API=anthropic       or "openai"
#   VIBEGUARD_LLM_API_KEY=<provider key>
#   VIBEGUARD_LLM_MODEL=claude-opus-5
# Cost control (see lib/cost.js):
#   VIBEGUARD_LLM_MAX_USD=0.50        hard spend ceiling per scan, 0 disables
#   VIBEGUARD_LLM_PRICE_IN / _OUT     $/M tokens, for models we don't price by default
# Optional tuning:
#   VIBEGUARD_CONCURRENCY=2           scans running at once
#   VIBEGUARD_MAX_QUEUE=20            scans allowed to wait
#   VIBEGUARD_RATE_MAX=5              scans per IP per hour
#   VIBEGUARD_MAX_FILES=4000         repo file cap
#   VIBEGUARD_MAX_TOTAL_BYTES=40000000
#   VIBEGUARD_ALLOWED_HOSTS=github.com,gitlab.com,bitbucket.org
#   VIBEGUARD_PROXY_HOPS=1           trusted reverse-proxy hops for client-IP rate limiting
# Optional "email me the report" (Resend); feature stays off unless both are set:
#   VIBEGUARD_EMAIL_API_KEY=re_...
#   VIBEGUARD_EMAIL_FROM=VibeGuard <reports@yourdomain.com>
#   VIBEGUARD_EMAIL_BCC=you@yourdomain.com   (optional lead-capture copy)

CMD ["node", "server.js"]
