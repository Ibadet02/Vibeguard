# VibeGuard hosted scanner.
# Node 22 (for native .env loading) + git (to clone repos) + the Claude Code CLI
# (which powers the AI reasoning pass via the freemodel backend for now).

FROM node:22-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# The AI reasoning pass shells out to the real Claude Code binary.
RUN npm install -g @anthropic-ai/claude-code

# Run as non-root: Claude Code refuses --dangerously-skip-permissions under root.
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
#   VIBEGUARD_LLM_BASE_URL=https://cc-t2.freemodel.dev
#   VIBEGUARD_LLM_API_KEY=<your freemodel key>
# Optional tuning:
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
